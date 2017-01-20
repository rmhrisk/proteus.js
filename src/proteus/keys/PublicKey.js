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

var CBOR, ClassUtil, DontCallConstructor, PublicKey, TypeUtil, ed2curve, sodium;

CBOR = require('wire-webapp-cbor');

ed2curve = require('ed2curve');

sodium = require('libsodium');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

module.exports = PublicKey = (function() {
  function PublicKey() {
    throw new DontCallConstructor(this);
  }

  PublicKey["new"] = function(pub_edward, pub_curve) {
    var pk;
    TypeUtil.assert_is_instance(Uint8Array, pub_edward);
    TypeUtil.assert_is_instance(Uint8Array, pub_curve);
    pk = ClassUtil.new_instance(PublicKey);
    pk.pub_edward = pub_edward;
    pk.pub_curve = pub_curve;
    return pk;
  };


  /*
   * This function can be used to verify a message signature.
   *
   * @param signature [Uint8Array] The signature to verify
   * @param message [String] The message from which the signature was computed.
   * @return [bool] `true` if the signature is valid, `false` otherwise.
   */

  PublicKey.prototype.verify = function(signature, message) {
    TypeUtil.assert_is_instance(Uint8Array, signature);
    return sodium.crypto_sign_verify_detached(signature, message, this.pub_edward);
  };

  PublicKey.prototype.fingerprint = function() {
    return sodium.to_hex(this.pub_edward);
  };

  PublicKey.prototype.encode = function(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.pub_edward);
  };

  PublicKey.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(PublicKey);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.pub_edward = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(Uint8Array, self.pub_edward);
    self.pub_curve = ed2curve.convertPublicKey(self.pub_edward);
    return self;
  };

  return PublicKey;

})();
