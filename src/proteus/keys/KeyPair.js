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
const ed2curve = require('ed2curve');
const sodium = require('libsodium');

const DontCallConstructor = require('../errors/DontCallConstructor');
const ClassUtil = require('../util/ClassUtil');
const TypeUtil = require('../util/TypeUtil');

const PublicKey = require('./PublicKey');
const SecretKey = require('./SecretKey');

/*
 * Construct an ephemeral key pair.
 */
module.exports = class KeyPair {
  constructor () {
    throw new DontCallConstructor(this);
  }

  static new () {
    const ed25519_key_pair = sodium.crypto_sign_keypair();

    const kp = ClassUtil.new_instance(KeyPair);
    kp.secret_key = KeyPair.prototype._construct_private_key(ed25519_key_pair);
    kp.public_key = KeyPair.prototype._construct_public_key(ed25519_key_pair);

    return kp;
  }

  /*
   * @note Ed25519 keys can be converted to Curve25519 keys, so that the same key pair can be
   * used both for authenticated encryption (crypto_box) and for signatures (crypto_sign).
   * @param ed25519_key_pair [Object] Key pair based on Edwards-curve (Ed25519)
   * @option ed25519_key_pair [Uint8Array[32]] publicKey
   * @option ed25519_key_pair [Uint8Array[64]] privateKey
   * @option ed25519_key_pair [String] keyType
   * @return [Proteus.keys.SecretKey] Constructed private key
   * @see https://download.libsodium.org/doc/advanced/ed25519-curve25519.html
   */
  _construct_private_key (ed25519_key_pair) {
    const sk_ed25519 = ed25519_key_pair.privateKey;
    const sk_curve25519 = ed2curve.convertSecretKey(sk_ed25519);
    return SecretKey.new(sk_ed25519, sk_curve25519);
  }

  /*
   * @param ed25519_key_pair [libsodium.KeyPair] Key pair based on Edwards-curve (Ed25519)
   * @return [Proteus.keys.PublicKey] Constructed public key
   */
  _construct_public_key (ed25519_key_pair) {
    const pk_ed25519 = ed25519_key_pair.publicKey;
    const pk_curve25519 = ed2curve.convertPublicKey(pk_ed25519);
    return PublicKey.new(pk_ed25519, pk_curve25519);
  }

  encode (e) {
    e.object(2);

    e.u8(0);
    this.secret_key.encode(e);

    e.u8(1);
    return this.public_key.encode(e);
  }

  static decode (d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(KeyPair);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
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
  }
};
