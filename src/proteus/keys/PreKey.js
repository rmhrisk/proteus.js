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

var CBOR, ClassUtil, DontCallConstructor, KeyPair, PreKey, TypeUtil;

CBOR = require('wire-webapp-cbor');
DontCallConstructor = require('../errors/DontCallConstructor');
ClassUtil = require('../util/ClassUtil');
TypeUtil = require('../util/TypeUtil');
KeyPair = require('./KeyPair');

/*
 * Pre-generated (and regularly refreshed) pre-keys.
 * A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
 */
module.exports = PreKey = (function() {
  PreKey.MAX_PREKEY_ID = 0xFFFF;

  function PreKey() {
    throw new DontCallConstructor(this);
  }

  /*
   * @param pre_key_id [Integer]
   */
  PreKey.new = function(pre_key_id) {
    var pk;
    TypeUtil.assert_is_integer(pre_key_id);
    if (pre_key_id < 0 || pre_key_id > PreKey.MAX_PREKEY_ID) {
      throw new RangeError('Argument pre_key_id (' + pre_key_id + ') must be between 0 (inclusive) and ' + PreKey.MAX_PREKEY_ID + ' (inclusive).');
    }
    pk = ClassUtil.new_instance(PreKey);
    pk.version = 1;
    pk.key_id = pre_key_id;
    pk.key_pair = KeyPair.new();
    return pk;
  };

  PreKey.last_resort = function() {
    return PreKey.new(PreKey.MAX_PREKEY_ID);
  };

  PreKey.generate_prekeys = function(start, size) {
    var check_integer, i, ref, results;
    check_integer = function(value) {
      TypeUtil.assert_is_integer(value);
      if (value < 0 || value > PreKey.MAX_PREKEY_ID) {
        throw new RangeError('Arguments must be between 0 (inclusive) and ' + PreKey.MAX_PREKEY_ID + ' (inclusive).');
      }
    };
    check_integer(start);
    check_integer(size);
    if (size === 0) {
      return [];
    }
    return (function() {
      results = [];
      for (var i = 0, ref = size - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--){ results.push(i); }
      return results;
    }).apply(this).map(function(x) {
      return PreKey.new((start + x) % PreKey.MAX_PREKEY_ID);
    });
  };

  PreKey.prototype.serialise = function() {
    var e;
    e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  };

  PreKey.deserialise = function(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return PreKey.decode(new CBOR.Decoder(buf));
  };

  PreKey.prototype.encode = function(e) {
    TypeUtil.assert_is_instance(CBOR.Encoder, e);
    e.object(3);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    e.u16(this.key_id);
    e.u8(2);
    return this.key_pair.encode(e);
  };

  PreKey.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(PreKey);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.key_id = d.u16();
          break;
        case 2:
          self.key_pair = KeyPair.decode(d);
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_integer(self.key_id);
    TypeUtil.assert_is_instance(KeyPair, self.key_pair);
    return self;
  };

  return PreKey;

})();
