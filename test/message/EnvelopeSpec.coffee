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

describe 'Envelope', ->
  mk = Proteus.derived.MacKey.new new Uint8Array(32).fill(1)
  bk = Proteus.keys.KeyPair.new().public_key
  ik = Proteus.keys.IdentityKey.new Proteus.keys.KeyPair.new().public_key
  rk = Proteus.keys.KeyPair.new().public_key

  tg = Proteus.message.SessionTag.new()

  it 'should encapsulate a CipherMessage', ->
    msg = Proteus.message.CipherMessage.new tg, 42, 3, rk, new Uint8Array([1, 2, 3, 4, 5])

    env = Proteus.message.Envelope.new mk, msg
    assert(env.verify mk)

  it 'should encapsulate a PreKeyMessage', ->
    msg = Proteus.message.PreKeyMessage.new(
      42, bk, ik, Proteus.message.CipherMessage.new(
        tg, 42, 43, rk, new Uint8Array([1, 2, 3, 4])))

    env = Proteus.message.Envelope.new mk, msg
    assert(env.verify mk)

  it 'should encode to and decode from CBOR', ->
    msg = Proteus.message.PreKeyMessage.new(
      42, bk, ik, Proteus.message.CipherMessage.new(
        tg, 42, 43, rk, new Uint8Array([1, 2, 3, 4])))

    env = Proteus.message.Envelope.new mk, msg
    assert(env.verify mk)

    env_bytes = env.serialise()
    env_cpy = Proteus.message.Envelope.deserialise env_bytes

    assert(env_cpy.verify mk)
