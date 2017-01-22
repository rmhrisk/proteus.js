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

const IdentityKeyPair = require('./IdentityKeyPair');
const IdentityKey = require('./IdentityKey');
const PreKeyAuth = require('./PreKeyAuth');
const PublicKey = require('./PublicKey');
const PreKey = require('./PreKey');

module.exports = class PreKeyBundle {
  constructor () {
    throw new DontCallConstructor(this);
  }

  /*
   * @param public_identity_key [Proteus.keys.IdentityKey]
   * @param prekey [Proteus.keys.PreKey]
   */
  static new (public_identity_key, prekey) {
    TypeUtil.assert_is_instance(IdentityKey, public_identity_key);
    TypeUtil.assert_is_instance(PreKey, prekey);

    const bundle = ClassUtil.new_instance(PreKeyBundle);

    bundle.version = 1;
    bundle.prekey_id = prekey.key_id;
    bundle.public_key = prekey.key_pair.public_key;
    bundle.identity_key = public_identity_key;
    bundle.signature = null;

    return bundle;
  }

  static signed (identity_pair, prekey) {
    TypeUtil.assert_is_instance(IdentityKeyPair, identity_pair);
    TypeUtil.assert_is_instance(PreKey, prekey);

    const ratchet_key = prekey.key_pair.public_key;
    const signature = identity_pair.secret_key.sign(ratchet_key.pub_edward);

    const bundle = ClassUtil.new_instance(PreKeyBundle);

    bundle.version = 1;
    bundle.prekey_id = prekey.key_id;
    bundle.public_key = ratchet_key;
    bundle.identity_key = identity_pair.public_key;
    bundle.signature = signature;

    return bundle;
  }

  verify () {
    if (!this.signature) {
      return PreKeyAuth.UNKNOWN;
    }

    if (this.identity_key.public_key.verify(this.signature, this.public_key.pub_edward)) {
      return PreKeyAuth.VALID;
    }
    return PreKeyAuth.INVALID;
  }

  serialise () {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  serialised_json () {
    return {
      'id': this.prekey_id,
      'key': sodium.to_base64(new Uint8Array(this.serialise()), true)
    };
  }

  static deserialise (buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return PreKeyBundle.decode(new CBOR.Decoder(buf));
  }

  encode (e) {
    TypeUtil.assert_is_instance(CBOR.Encoder, e);

    e.object(5);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    e.u16(this.prekey_id);
    e.u8(2);
    this.public_key.encode(e);
    e.u8(3);
    this.identity_key.encode(e);

    e.u8(4);
    if (!this.signature) {
      return e.null();
    } else {
      return e.bytes(this.signature);
    }
  }

  static decode (d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(PreKeyBundle);

    const nprops = d.object();
    for (let i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.prekey_id = d.u16();
          break;
        case 2:
          self.public_key = PublicKey.decode(d);
          break;
        case 3:
          self.identity_key = IdentityKey.decode(d);
          break;
        case 4:
          self.signature = d.optional(() => new Uint8Array(d.bytes()));
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_integer(self.prekey_id);
    TypeUtil.assert_is_instance(PublicKey, self.public_key);
    TypeUtil.assert_is_instance(IdentityKey, self.identity_key);

    return self;
  }
};
