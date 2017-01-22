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

var CBOR, CipherKey, ClassUtil, DontCallConstructor, TypeUtil, sodium;

CBOR = require('wire-webapp-cbor');

sodium = require('libsodium');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

module.exports = CipherKey = (function() {
  function CipherKey() {
    throw new DontCallConstructor(this);
  }

  CipherKey.new = function(key) {
    var ck;
    TypeUtil.assert_is_instance(Uint8Array, key);
    ck = ClassUtil.new_instance(CipherKey);
    ck.key = key;
    return ck;
  };


  /*
   * @param plaintext [String, Uint8Array, ArrayBuffer] The text to encrypt
   * @param nonce [Uint8Array] Counter as nonce
   * @return [Uint8Array] Encypted payload
   */

  CipherKey.prototype.encrypt = function(plaintext, nonce) {

    // @todo Re-validate if the ArrayBuffer check is needed (Prerequisite: Integration tests)
    if (plaintext instanceof ArrayBuffer && plaintext.byteLength !== void 0) {
      plaintext = new Uint8Array(plaintext);
    }
    return sodium.crypto_stream_chacha20_xor(plaintext, nonce, this.key, 'uint8array');
  };

  CipherKey.prototype.decrypt = function(ciphertext, nonce) {
    return this.encrypt(ciphertext, nonce);
  };

  CipherKey.prototype.encode = function(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.key);
  };

  CipherKey.decode = function(d) {
    var i, key_bytes, nprops, ref;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    key_bytes = null;
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          key_bytes = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    return CipherKey.new(key_bytes);
  };

  return CipherKey;

})();
