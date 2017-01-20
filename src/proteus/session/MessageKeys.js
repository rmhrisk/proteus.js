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

var CBOR, CipherKey, ClassUtil, DontCallConstructor, MacKey, MessageKeys, TypeUtil;

CBOR = require('wire-webapp-cbor');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

MacKey = require('../derived/MacKey');

CipherKey = require('../derived/CipherKey');

module.exports = MessageKeys = (function() {
  function MessageKeys() {
    throw new DontCallConstructor(this);
  }

  MessageKeys.new = function(cipher_key, mac_key, counter) {
    var mk;
    TypeUtil.assert_is_instance(CipherKey, cipher_key);
    TypeUtil.assert_is_instance(MacKey, mac_key);
    TypeUtil.assert_is_integer(counter);
    mk = ClassUtil.new_instance(MessageKeys);
    mk.cipher_key = cipher_key;
    mk.mac_key = mac_key;
    mk.counter = counter;
    return mk;
  };

  MessageKeys.prototype._counter_as_nonce = function() {
    var nonce;
    nonce = new ArrayBuffer(8);
    new DataView(nonce).setUint32(0, this.counter);
    return new Uint8Array(nonce);
  };

  MessageKeys.prototype.encrypt = function(plaintext) {
    return this.cipher_key.encrypt(plaintext, this._counter_as_nonce());
  };

  MessageKeys.prototype.decrypt = function(ciphertext) {
    return this.cipher_key.decrypt(ciphertext, this._counter_as_nonce());
  };

  MessageKeys.prototype.encode = function(e) {
    e.object(3);
    e.u8(0);
    this.cipher_key.encode(e);
    e.u8(1);
    this.mac_key.encode(e);
    e.u8(2);
    return e.u32(this.counter);
  };

  MessageKeys.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(MessageKeys);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.cipher_key = CipherKey.decode(d);
          break;
        case 1:
          self.mac_key = MacKey.decode(d);
          break;
        case 2:
          self.counter = d.u32();
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(CipherKey, self.cipher_key);
    TypeUtil.assert_is_instance(MacKey, self.mac_key);
    TypeUtil.assert_is_integer(self.counter);
    return self;
  };

  return MessageKeys;

})();
