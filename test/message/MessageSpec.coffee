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

describe 'Message', ->
  fake_pubkey = (byte) ->
    pub_edward = new Uint8Array 32
    pub_edward.fill(byte)
    pub_curve = sodium.crypto_sign_ed25519_pk_to_curve25519 pub_edward

    return Proteus.keys.PublicKey.new pub_edward, pub_curve

  bk = fake_pubkey(0xFF)
  ik = Proteus.keys.IdentityKey.new fake_pubkey(0xA0)
  rk = fake_pubkey(0xF0)

  st = Proteus.message.SessionTag.new()
  st.tag.fill 42

  it 'should serialise and deserialise a CipherMessage correctly', ->
    expected = '01a500502a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a010c020d03a1005820f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0044a0102030405060708090a'

    msg = Proteus.message.CipherMessage.new st, 12, 13, rk, new Uint8Array([1..10])

    bytes = new Uint8Array msg.serialise()
    assert(expected is sodium.to_hex(bytes).toLowerCase())

    deserialised = Proteus.message.Message.deserialise bytes.buffer
    assert(deserialised.constructor is Proteus.message.CipherMessage)
    assert(deserialised.ratchet_key.fingerprint() is rk.fingerprint())

  it 'should serialise a PreKeyMessage correctly', ->
    expected = '02a400181801a1005820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff02a100a1005820a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a003a500502a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a010c020d03a1005820f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0044a0102030405060708090a'

    cmsg = Proteus.message.CipherMessage.new st, 12, 13, rk, new Uint8Array([1..10])
    pkmsg = Proteus.message.PreKeyMessage.new 24, bk, ik, cmsg

    bytes = new Uint8Array pkmsg.serialise()
    assert(expected is sodium.to_hex(bytes).toLowerCase())

    deserialised = Proteus.message.Message.deserialise bytes.buffer
    assert(deserialised.constructor is Proteus.message.PreKeyMessage)

    assert(deserialised.base_key.fingerprint() is bk.fingerprint())
    assert(deserialised.identity_key.fingerprint() is ik.fingerprint())

    assert(deserialised.message.ratchet_key.fingerprint() is rk.fingerprint())
