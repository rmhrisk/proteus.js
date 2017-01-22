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

const DontCallConstructor = require('../errors/DontCallConstructor');
const ClassUtil = require('../util/ClassUtil');
const TypeUtil = require('../util/TypeUtil');

const KeyPair = require('./KeyPair');
/*
 * Pre-generated (and regularly refreshed) pre-keys.
 * A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
 */
class PreKey {
  constructor () {
    throw new DontCallConstructor(this);
  }

  /*
   * @param pre_key_id [Integer]
   */
  static new (pre_key_id) {
    TypeUtil.assert_is_integer(pre_key_id);

    if (pre_key_id < 0 || pre_key_id > PreKey.MAX_PREKEY_ID) {
      throw new RangeError(
        `Argument pre_key_id (${pre_key_id}) must be between 0 (inclusive) and ${PreKey.MAX_PREKEY_ID} (inclusive).`
      );
    }

    const pk = ClassUtil.new_instance(PreKey);

    pk.version = 1;
    pk.key_id = pre_key_id;
    pk.key_pair = KeyPair.new();
    return pk;
  }

  static last_resort () {
    return PreKey.new(PreKey.MAX_PREKEY_ID);
  }

  static generate_prekeys (start, size) {
    const check_integer = (value) => {
      TypeUtil.assert_is_integer(value);

      if (value < 0 || value > PreKey.MAX_PREKEY_ID) {
        throw new RangeError(
          `Arguments must be between 0 (inclusive) and ${PreKey.MAX_PREKEY_ID} (inclusive).`
        );
      }
    };

    check_integer(start);
    check_integer(size);

    if (size === 0) {
      return [];
    }

    return (function () {
      let results = [];
      for (let i = 0, ref = size - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--){
        results.push(i);
      }
      return results;
    }).apply(this).map((x) => PreKey.new((start + x) % PreKey.MAX_PREKEY_ID));
  }

  serialise () {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  static deserialise (buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return PreKey.decode(new CBOR.Decoder(buf));
  }

  encode (e) {
    TypeUtil.assert_is_instance(CBOR.Encoder, e);
    e.object(3);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    e.u16(this.key_id);
    e.u8(2);
    return this.key_pair.encode(e);
  }

  static decode (d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(PreKey);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
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
  }
}

PreKey.MAX_PREKEY_ID = 0xFFFF;
module.exports = PreKey;
