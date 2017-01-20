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

var CBOR, ChainKey, ClassUtil, DerivedSecrets, DontCallConstructor, MacKey, MessageKeys, TypeUtil;

CBOR = require('wire-webapp-cbor');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

MacKey = require('../derived/MacKey');

DerivedSecrets = require('../derived/DerivedSecrets');

MessageKeys = require('./MessageKeys');

module.exports = ChainKey = (function() {
  function ChainKey() {
    throw new DontCallConstructor(this);
  }


  /*
   * @param key [Proteus.derived.MacKey] Mac Key generated by derived secrets
   */

  ChainKey.from_mac_key = function(key, counter) {
    var ck;
    TypeUtil.assert_is_instance(MacKey, key);
    TypeUtil.assert_is_integer(counter);
    ck = ClassUtil.new_instance(ChainKey);
    ck.key = key;
    ck.idx = counter;
    return ck;
  };

  ChainKey.prototype.next = function() {
    var ck;
    ck = ClassUtil.new_instance(ChainKey);
    ck.key = MacKey["new"](this.key.sign('1'));
    ck.idx = this.idx + 1;
    return ck;
  };

  ChainKey.prototype.message_keys = function() {
    var base, dsecs;
    base = this.key.sign('0');
    dsecs = DerivedSecrets.kdf_without_salt(base, 'hash_ratchet');
    return MessageKeys["new"](dsecs.cipher_key, dsecs.mac_key, this.idx);
  };

  ChainKey.prototype.encode = function(e) {
    e.object(2);
    e.u8(0);
    this.key.encode(e);
    e.u8(1);
    return e.u32(this.idx);
  };

  ChainKey.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(ChainKey);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.key = MacKey.decode(d);
          break;
        case 1:
          self.idx = d.u32();
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(MacKey, self.key);
    TypeUtil.assert_is_integer(self.idx);
    return self;
  };

  return ChainKey;

})();