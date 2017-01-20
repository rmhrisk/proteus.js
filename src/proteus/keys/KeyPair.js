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

var CBOR, ClassUtil, DontCallConstructor, KeyPair, PublicKey, SecretKey, TypeUtil, ed2curve, sodium;

CBOR = require('wire-webapp-cbor');

ed2curve = require('ed2curve');

sodium = require('libsodium');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

PublicKey = require('./PublicKey');

SecretKey = require('./SecretKey');


//Construct an ephemeral key pair.

module.exports = KeyPair = (function() {
  function KeyPair() {
    throw new DontCallConstructor(this);
  }

  KeyPair["new"] = function() {
    var ed25519_key_pair, kp;
    ed25519_key_pair = sodium.crypto_sign_keypair();
    kp = ClassUtil.new_instance(KeyPair);
    kp.secret_key = KeyPair.prototype._construct_private_key(ed25519_key_pair);
    kp.public_key = KeyPair.prototype._construct_public_key(ed25519_key_pair);
    return kp;
  };


  /*
   * @note Ed25519 keys can be converted to Curve25519 keys, so that the same key pair can be used both for authenticated encryption (crypto_box) and for signatures (crypto_sign).
   * @param ed25519_key_pair [Object] Key pair based on Edwards-curve (Ed25519)
   * @option ed25519_key_pair [Uint8Array[32]] publicKey
   * @option ed25519_key_pair [Uint8Array[64]] privateKey
   * @option ed25519_key_pair [String] keyType
   * @return [Proteus.keys.SecretKey] Constructed private key
   * @see https://download.libsodium.org/doc/advanced/ed25519-curve25519.html
   */

  KeyPair.prototype._construct_private_key = function(ed25519_key_pair) {
    var sk_curve25519, sk_ed25519;
    sk_ed25519 = ed25519_key_pair.privateKey;
    sk_curve25519 = ed2curve.convertSecretKey(sk_ed25519);
    return SecretKey["new"](sk_ed25519, sk_curve25519);
  };


  /*
   * @param ed25519_key_pair [libsodium.KeyPair] Key pair based on Edwards-curve (Ed25519)
   * @return [Proteus.keys.PublicKey] Constructed public key
   */

  KeyPair.prototype._construct_public_key = function(ed25519_key_pair) {
    var pk_curve25519, pk_ed25519;
    pk_ed25519 = ed25519_key_pair.publicKey;
    pk_curve25519 = ed2curve.convertPublicKey(pk_ed25519);
    return PublicKey["new"](pk_ed25519, pk_curve25519);
  };

  KeyPair.prototype.encode = function(e) {
    e.object(2);
    e.u8(0);
    this.secret_key.encode(e);
    e.u8(1);
    return this.public_key.encode(e);
  };

  KeyPair.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(KeyPair);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.secret_key = SecretKey.decode(d);
          break;
        case 1:
          self.public_key = PublicKey.decode(d);
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(SecretKey, self.secret_key);
    TypeUtil.assert_is_instance(PublicKey, self.public_key);
    return self;
  };

  return KeyPair;

})();
