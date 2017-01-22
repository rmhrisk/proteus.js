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

const CBOR = require('wire-webapp-cbor');
const sodium = require('libsodium');

const DontCallConstructor = require('../errors/DontCallConstructor');
const ClassUtil = require('../util/ClassUtil');
const TypeUtil = require('../util/TypeUtil');

module.exports = class CipherKey {
  constructor () {
    throw new DontCallConstructor(this);
  }

  static new (key) {
    TypeUtil.assert_is_instance(Uint8Array, key);

    const ck = ClassUtil.new_instance(CipherKey);
    ck.key = key;
    return ck;
  }

  /*
   * @param plaintext [String, Uint8Array, ArrayBuffer] The text to encrypt
   * @param nonce [Uint8Array] Counter as nonce
   * @return [Uint8Array] Encypted payload
   */
  encrypt (plaintext, nonce) {

    // @todo Re-validate if the ArrayBuffer check is needed (Prerequisite: Integration tests)
    if (plaintext instanceof ArrayBuffer && plaintext.byteLength !== undefined) {
      plaintext = new Uint8Array(plaintext);
    }

    return sodium.crypto_stream_chacha20_xor(plaintext, nonce, this.key, 'uint8array');
  }

  decrypt (ciphertext, nonce) {
    return this.encrypt(ciphertext, nonce);
  }

  encode (e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.key);
  }

  static decode (d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    let key_bytes = null;

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          key_bytes = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    return CipherKey.new(key_bytes);
  }
};
