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

var CBOR, ClassUtil, DontCallConstructor, IdentityKey, IdentityKeyPair, PreKey, PreKeyAuth, PreKeyBundle, PublicKey, TypeUtil, sodium;

CBOR = require('wire-webapp-cbor');
sodium = require('libsodium');
DontCallConstructor = require('../errors/DontCallConstructor');
ClassUtil = require('../util/ClassUtil');
TypeUtil = require('../util/TypeUtil');
IdentityKeyPair = require('./IdentityKeyPair');
IdentityKey = require('./IdentityKey');
PreKeyAuth = require('./PreKeyAuth');
PublicKey = require('./PublicKey');
PreKey = require('./PreKey');

module.exports = PreKeyBundle = (function() {
  function PreKeyBundle() {
    throw new DontCallConstructor(this);
  }

  /*
   * @param public_identity_key [Proteus.keys.IdentityKey]
   * @param prekey [Proteus.keys.PreKey]
   */
  PreKeyBundle.new = function(public_identity_key, prekey) {
    var bundle;
    TypeUtil.assert_is_instance(IdentityKey, public_identity_key);
    TypeUtil.assert_is_instance(PreKey, prekey);
    bundle = ClassUtil.new_instance(PreKeyBundle);
    bundle.version = 1;
    bundle.prekey_id = prekey.key_id;
    bundle.public_key = prekey.key_pair.public_key;
    bundle.identity_key = public_identity_key;
    bundle.signature = null;
    return bundle;
  };

  PreKeyBundle.signed = function(identity_pair, prekey) {
    var bundle, ratchet_key, signature;
    TypeUtil.assert_is_instance(IdentityKeyPair, identity_pair);
    TypeUtil.assert_is_instance(PreKey, prekey);
    ratchet_key = prekey.key_pair.public_key;
    signature = identity_pair.secret_key.sign(ratchet_key.pub_edward);
    bundle = ClassUtil.new_instance(PreKeyBundle);
    bundle.version = 1;
    bundle.prekey_id = prekey.key_id;
    bundle.public_key = ratchet_key;
    bundle.identity_key = identity_pair.public_key;
    bundle.signature = signature;
    return bundle;
  };

  PreKeyBundle.prototype.verify = function() {
    if (!this.signature) {
      return PreKeyAuth.UNKNOWN;
    }
    if (this.identity_key.public_key.verify(this.signature, this.public_key.pub_edward)) {
      return PreKeyAuth.VALID;
    }
    return PreKeyAuth.INVALID;
  };

  PreKeyBundle.prototype.serialise = function() {
    var e;
    e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  };

  PreKeyBundle.prototype.serialised_json = function() {
    return {
      'id': this.prekey_id,
      'key': sodium.to_base64(new Uint8Array(this.serialise()), true)
    };
  };

  PreKeyBundle.deserialise = function(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return PreKeyBundle.decode(new CBOR.Decoder(buf));
  };

  PreKeyBundle.prototype.encode = function(e) {
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
  };

  PreKeyBundle.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(PreKeyBundle);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
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
          self.signature = d.optional(function() {
            return new Uint8Array(d.bytes());
          });
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
  };

  return PreKeyBundle;

})();
