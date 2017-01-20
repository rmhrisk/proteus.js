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

var CBOR, ClassUtil, DontCallConstructor, IdentityKey, IdentityKeyPair, KeyPair, SecretKey, TypeUtil;

CBOR = require('wire-webapp-cbor');
DontCallConstructor = require('../errors/DontCallConstructor');
ClassUtil = require('../util/ClassUtil');
TypeUtil = require('../util/TypeUtil');
IdentityKey = require('./IdentityKey');
SecretKey = require('./SecretKey');
KeyPair = require('./KeyPair');

module.exports = IdentityKeyPair = (function() {
  function IdentityKeyPair() {
    throw new DontCallConstructor(this);
  }

  IdentityKeyPair.new = function() {
    var ikp, key_pair;
    key_pair = KeyPair.new();
    ikp = ClassUtil.new_instance(IdentityKeyPair);
    ikp.version = 1;
    ikp.secret_key = key_pair.secret_key;
    ikp.public_key = IdentityKey.new(key_pair.public_key);
    return ikp;
  };

  IdentityKeyPair.prototype.serialise = function() {
    var e;
    e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  };

  IdentityKeyPair.deserialise = function(buf) {
    var d;
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    d = new CBOR.Decoder(buf);
    return IdentityKeyPair.decode(d);
  };

  IdentityKeyPair.prototype.encode = function(e) {
    e.object(3);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    this.secret_key.encode(e);
    e.u8(2);
    return this.public_key.encode(e);
  };

  IdentityKeyPair.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(IdentityKeyPair);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.secret_key = SecretKey.decode(d);
          break;
        case 2:
          self.public_key = IdentityKey.decode(d);
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_instance(SecretKey, self.secret_key);
    TypeUtil.assert_is_instance(IdentityKey, self.public_key);
    return self;
  };

  return IdentityKeyPair;

})();
