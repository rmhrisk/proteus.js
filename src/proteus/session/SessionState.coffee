# Wire
# Copyright (C) 2016 Wire Swiss GmbH
# Based on libsignal-protocol-java by Open Whisper Systems
# https://github.com/WhisperSystems/libsignal-protocol-java
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

CBOR = require 'cbor-codec'

DontCallConstructor = require '../errors/DontCallConstructor'
ClassUtil = require '../util/ClassUtil'
TypeUtil = require '../util/TypeUtil'
ArrayUtil = require '../util/ArrayUtil'

DecryptError = require '../errors/DecryptError'

DerivedSecrets = require '../derived/DerivedSecrets'

IdentityKeyPair = require '../keys/IdentityKeyPair'
IdentityKey = require '../keys/IdentityKey'
PreKeyBundle = require '../keys/PreKeyBundle'
PublicKey = require '../keys/PublicKey'
KeyPair = require '../keys/KeyPair'

Envelope = require '../message/Envelope'
CipherMessage = require '../message/CipherMessage'
PreKeyMessage = require '../message/PreKeyMessage'
SessionTag = require '../message/SessionTag'

RecvChain = require './RecvChain'
SendChain = require './SendChain'
ChainKey = require './ChainKey'
RootKey = require './RootKey'
Session = require './Session'

module.exports = class SessionState
  constructor: ->
    @recv_chains = null
    @send_chain = null
    @root_key = null
    @prev_counter = null

    throw new DontCallConstructor @

  @init_as_alice: (alice_identity_pair, alice_base, bob_pkbundle) ->
    TypeUtil.assert_is_instance IdentityKeyPair, alice_identity_pair
    TypeUtil.assert_is_instance KeyPair, alice_base
    TypeUtil.assert_is_instance PreKeyBundle, bob_pkbundle

    master_key = ArrayUtil.concatenate_array_buffers([
      alice_identity_pair.secret_key.shared_secret(bob_pkbundle.public_key),
      alice_base.secret_key.shared_secret(bob_pkbundle.identity_key.public_key),
      alice_base.secret_key.shared_secret(bob_pkbundle.public_key)])

    dsecs = DerivedSecrets.kdf_without_salt master_key, "handshake"

    rootkey = RootKey.from_cipher_key dsecs.cipher_key
    chainkey = ChainKey.from_mac_key dsecs.mac_key, 0

    recv_chains = [RecvChain.new(chainkey, bob_pkbundle.public_key)]

    send_ratchet = KeyPair.new()
    [rok, chk] = rootkey.dh_ratchet send_ratchet, bob_pkbundle.public_key
    send_chain = SendChain.new chk, send_ratchet

    state = ClassUtil.new_instance SessionState
    state.recv_chains = recv_chains
    state.send_chain = send_chain
    state.root_key = rok
    state.prev_counter = 0
    return state

  @init_as_bob: (bob_ident, bob_prekey, alice_ident, alice_base) ->
    TypeUtil.assert_is_instance IdentityKeyPair, bob_ident
    TypeUtil.assert_is_instance KeyPair, bob_prekey
    TypeUtil.assert_is_instance IdentityKey, alice_ident
    TypeUtil.assert_is_instance PublicKey, alice_base

    master_key = ArrayUtil.concatenate_array_buffers([
      bob_prekey.secret_key.shared_secret(alice_ident.public_key),
      bob_ident.secret_key.shared_secret(alice_base),
      bob_prekey.secret_key.shared_secret(alice_base)])

    dsecs = DerivedSecrets.kdf_without_salt master_key, "handshake"

    rootkey = RootKey.from_cipher_key dsecs.cipher_key
    chainkey = ChainKey.from_mac_key dsecs.mac_key, 0
    send_chain = SendChain.new chainkey, bob_prekey

    state = ClassUtil.new_instance SessionState
    state.recv_chains = []
    state.send_chain = send_chain
    state.root_key = rootkey
    state.prev_counter = 0
    return state

  ratchet: (ratchet_key) ->
    new_ratchet = KeyPair.new()

    [recv_root_key, recv_chain_key] = @root_key.dh_ratchet @send_chain.ratchet_key, ratchet_key
    [send_root_key, send_chain_key] = recv_root_key.dh_ratchet new_ratchet, ratchet_key

    recv_chain = RecvChain.new recv_chain_key, ratchet_key
    send_chain = SendChain.new send_chain_key, new_ratchet

    @root_key = send_root_key
    @prev_counter = @send_chain.chain_key.idx
    @send_chain = send_chain

    @recv_chains.unshift recv_chain

    if @recv_chains.length > Session.MAX_RECV_CHAINS
      @recv_chains.pop()

    return

  ###
  @param identity_key [Proteus.keys.IdentityKey] Public identity key of the local identity key pair
  @param pending [] Pending pre-key
  @param tag [Proteus.message.SessionTag] Session tag
  @param plaintext [String] The plaintext to encrypt

  @return [Proteus.message.Envelope]
  ###
  encrypt: (identity_key, pending, tag, plaintext) ->
    if pending
      TypeUtil.assert_is_integer pending[0]
      TypeUtil.assert_is_instance PublicKey, pending[1]

    TypeUtil.assert_is_instance IdentityKey, identity_key
    TypeUtil.assert_is_instance SessionTag, tag

    msgkeys = @send_chain.chain_key.message_keys()

    message = CipherMessage.new(tag, @send_chain.chain_key.idx, @prev_counter,
      @send_chain.ratchet_key.public_key, msgkeys.encrypt(plaintext))

    if pending
      message = PreKeyMessage.new(pending[0], pending[1], identity_key, message)

    env = Envelope.new(msgkeys.mac_key, message)
    @send_chain.chain_key = @send_chain.chain_key.next()
    return env

  decrypt: (envelope, msg) ->
    TypeUtil.assert_is_instance Envelope, envelope
    TypeUtil.assert_is_instance CipherMessage, msg

    idx = -1
    found_index = @recv_chains.some (recv_chain, index) ->
      idx = index
      recv_chain.ratchet_key.fingerprint() is msg.ratchet_key.fingerprint()

    if not found_index
      @ratchet msg.ratchet_key
      idx = 0

    rc = @recv_chains[idx]
    switch
      when msg.counter < rc.chain_key.idx
        return rc.try_message_keys envelope, msg

      when msg.counter == rc.chain_key.idx
        mks = rc.chain_key.message_keys()

        if not envelope.verify mks.mac_key
          throw new DecryptError.InvalidSignature

        plain = mks.decrypt msg.cipher_text
        rc.chain_key = rc.chain_key.next()
        return plain

      when msg.counter > rc.chain_key.idx
        [chk, mk, mks] = rc.stage_message_keys msg

        if not envelope.verify mk.mac_key
          throw new DecryptError.InvalidSignature

        plain = mk.decrypt msg.cipher_text

        rc.chain_key = chk.next()
        rc.commit_message_keys mks

        return plain

  serialise: ->
    e = new CBOR.Encoder()
    @encode e
    return e.get_buffer()

  @deserialise: (buf) ->
    TypeUtil.assert_is_instance ArrayBuffer, buf
    return SessionState.decode new CBOR.Decoder buf

  encode: (e) ->
    e.object 4

    e.u8 0; e.array @recv_chains.length
    @recv_chains.map((rch) -> rch.encode e)

    e.u8 1; @send_chain.encode e
    e.u8 2; @root_key.encode e
    e.u8 3; e.u32 @prev_counter

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance SessionState

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0
          self.recv_chains = []

          len = d.array()
          while len--
            self.recv_chains.push RecvChain.decode d

        when 1 then self.send_chain   = SendChain.decode d
        when 2 then self.root_key     = RootKey.decode d
        when 3 then self.prev_counter = d.u32()
        else d.skip()

    TypeUtil.assert_is_instance Array, self.recv_chains
    TypeUtil.assert_is_instance SendChain, self.send_chain
    TypeUtil.assert_is_instance RootKey, self.root_key
    TypeUtil.assert_is_integer self.prev_counter

    return self
