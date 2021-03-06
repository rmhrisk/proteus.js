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

describe 'KeyPair', ->
  it 'signs a message and verifies the signature', ->
    kp = Proteus.keys.KeyPair.new()
    msg = "what do ya want for nothing?"

    sig = kp.secret_key.sign(msg)

    bad_sig = new Uint8Array(sig)
    for _, i in bad_sig
      bad_sig[i] = ~bad_sig[i]

    assert(kp.public_key.verify(sig, msg))
    assert(!kp.public_key.verify(bad_sig, msg))

  it 'computes a Diffie-Hellman shared secret', ->
    a = Proteus.keys.KeyPair.new()
    b = Proteus.keys.KeyPair.new()

    assert.deepEqual(
      a.secret_key.shared_secret(b.public_key),
      b.secret_key.shared_secret(a.public_key))
