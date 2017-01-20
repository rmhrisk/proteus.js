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

var CBOR, ClassUtil, DontCallConstructor, PublicKey, SecretKey, TypeUtil, ed2curve, sodium;

CBOR = require('wire-webapp-cbor');

ed2curve = require('ed2curve');

sodium = require('libsodium');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

PublicKey = require('./PublicKey');

module.exports = SecretKey = (function() {
  function SecretKey() {
    throw new DontCallConstructor(this);
  }

  SecretKey["new"] = function(sec_edward, sec_curve) {
    var sk;
    TypeUtil.assert_is_instance(Uint8Array, sec_edward);
    TypeUtil.assert_is_instance(Uint8Array, sec_curve);
    sk = ClassUtil.new_instance(SecretKey);
    sk.sec_edward = sec_edward;
    sk.sec_curve = sec_curve;
    return sk;
  };


  /*
   * This function can be used to compute a message signature.
   *
   * @param message [String] Message to be signed
   * @return [Uint8Array] A message signature
   */

  SecretKey.prototype.sign = function(message) {
    return sodium.crypto_sign_detached(message, this.sec_edward);
  };


  /*
   * This function can be used to compute a shared secret given a user's secret key and another
   * user's public key.
   *
   * @param public_key [Proteus.keys.PublicKey] Another user's public key
   * @return [Uint8Array] Array buffer view of the computed shared secret
   */

  SecretKey.prototype.shared_secret = function(public_key) {
    TypeUtil.assert_is_instance(PublicKey, public_key);
    return sodium.crypto_scalarmult(this.sec_curve, public_key.pub_curve);
  };

  SecretKey.prototype.encode = function(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.sec_edward);
  };

  SecretKey.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(SecretKey);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.sec_edward = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(Uint8Array, self.sec_edward);
    self.sec_curve = ed2curve.convertSecretKey(self.sec_edward);
    return self;
  };

  return SecretKey;

})();
