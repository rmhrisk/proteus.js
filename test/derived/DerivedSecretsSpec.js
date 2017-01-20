/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

describe('Key Derivation Function (KDF)', function() {
  it('generates Cipher Key and Mac Key', function() {
    var cipher_key, derived_secret, expected_cipher_key, expected_mac_key, info, input, mac_key;
    input = new Uint8Array([80, 126, 195, 116, 121, 19, 181, 29, 146, 68, 194, 215, 190, 132, 202, 217, 199, 26, 91, 4, 184, 156, 73, 204, 158, 76, 129, 220, 126, 178, 210, 92]);
    expected_cipher_key = new Uint8Array([22, 57, 15, 160, 231, 231, 169, 183, 205, 22, 179, 228, 53, 51, 14, 24, 160, 45, 247, 19, 106, 21, 78, 92, 110, 56, 24, 84, 156, 117, 177, 176]);
    expected_mac_key = new Uint8Array([186, 163, 142, 225, 211, 131, 100, 164, 80, 51, 180, 42, 177, 132, 72, 250, 246, 241, 41, 108, 146, 140, 247, 197, 205, 242, 32, 150, 186, 122, 45, 57]);
    info = "hash_ratchet";
    derived_secret = Proteus.derived.DerivedSecrets.kdf_without_salt(input, info);
    cipher_key = derived_secret.cipher_key.key;
    mac_key = derived_secret.mac_key.key;
    assert.deepEqual(cipher_key, expected_cipher_key);
    assert(cipher_key.byteLength === 32);
    assert.deepEqual(mac_key, expected_mac_key);
    return assert(mac_key.byteLength === 32);
  });
  return it('can encrypt and decrypt text', function() {
    var decrypted_text, derived_secret, encrypted_text, info, input, nonce, plain_text;
    info = 'foobar';
    input = sodium.from_string('346234876');
    nonce = sodium.from_string('00000000');
    plain_text = sodium.from_string('plaintext');
    derived_secret = Proteus.derived.DerivedSecrets.kdf_without_salt(input, info);
    encrypted_text = derived_secret.cipher_key.encrypt(plain_text, nonce);
    assert.notDeepEqual(encrypted_text, plain_text);
    decrypted_text = derived_secret.cipher_key.decrypt(encrypted_text, nonce);
    return assert.deepEqual(decrypted_text, plain_text);
  });
});
