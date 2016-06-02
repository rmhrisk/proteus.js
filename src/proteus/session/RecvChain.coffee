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

PublicKey = require '../keys/PublicKey'

ProteusError = require '../errors/ProteusError'
DecryptError = require '../errors/DecryptError'

Envelope = require '../message/Envelope'
CipherMessage = require '../message/CipherMessage'

MessageKeys = require './MessageKeys'
ChainKey = require './ChainKey'

module.exports = class RecvChain
  @MAX_COUNTER_GAP: 1000

  constructor: ->
    throw new DontCallConstructor @

  @new: (chain_key, public_key) ->
    TypeUtil.assert_is_instance ChainKey, chain_key
    TypeUtil.assert_is_instance PublicKey, public_key

    rc = ClassUtil.new_instance RecvChain
    rc.chain_key = chain_key
    rc.ratchet_key = public_key
    rc.message_keys = []
    return rc

  try_message_keys: (envelope, msg) ->
    TypeUtil.assert_is_instance Envelope, envelope
    TypeUtil.assert_is_instance CipherMessage, msg

    if @message_keys[0] && @message_keys[0].counter > msg.counter
      throw new DecryptError.OutdatedMessage

    idx = -1
    found_index = @message_keys.some (message_key, index) ->
      idx = index
      message_key.counter is msg.counter

    if not found_index
      throw new DecryptError.DuplicateMessage

    mk = @message_keys.splice(idx, 1)[0]
    if not envelope.verify mk.mac_key
      throw new DecryptError.InvalidSignature

    return mk.decrypt msg.cipher_text

  stage_message_keys: (msg) ->
    TypeUtil.assert_is_instance CipherMessage, msg

    num = msg.counter - @chain_key.idx
    if num > RecvChain.MAX_COUNTER_GAP
      throw new DecryptError.TooDistantFuture

    keys = []
    chk = @chain_key

    for _ in [0..(num - 1)]
      keys.push chk.message_keys()
      chk = chk.next()

    mk = chk.message_keys()
    return [chk, mk, keys]

  commit_message_keys: (keys) ->
    TypeUtil.assert_is_instance Array, keys
    keys.map((k) -> TypeUtil.assert_is_instance MessageKeys, k)

    if keys.length > RecvChain.MAX_COUNTER_GAP
      throw new ProteusError 'More keys than MAX_COUNTER_GAP'

    excess = @message_keys.length + keys.length - RecvChain.MAX_COUNTER_GAP

    for _ in [0..(excess - 1)]
      @message_keys.shift()

    keys.map((k) => @message_keys.push(k))

    if keys.length > RecvChain.MAX_COUNTER_GAP
      throw new ProteusError 'Skipped keys greater than MAX_COUNTER_GAP'

  encode: (e) ->
    e.object 3
    e.u8 0; @chain_key.encode e
    e.u8 1; @ratchet_key.encode e

    e.u8 2; e.array @message_keys.length
    @message_keys.map((k) -> k.encode e)

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance RecvChain

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.chain_key   = ChainKey.decode d
        when 1 then self.ratchet_key = PublicKey.decode d
        when 2
          self.message_keys = []

          len = d.array()
          while len--
            self.message_keys.push MessageKeys.decode d

        else d.skip()

    TypeUtil.assert_is_instance ChainKey, self.chain_key
    TypeUtil.assert_is_instance PublicKey, self.ratchet_key
    TypeUtil.assert_is_instance Array, self.message_keys

    return self
