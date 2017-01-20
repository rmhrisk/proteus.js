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

var CBOR, ClassUtil, DontCallConstructor, IdentityKey, PublicKey, TypeUtil, sodium;

CBOR = require('wire-webapp-cbor');

sodium = require('libsodium');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

PublicKey = require('./PublicKey');


/*
 * Construct a long-term identity key pair.
 *
 * Every client has a long-term identity key pair.
 * Long-term identity keys are used to initialise “sessions” with other clients (triple DH).
 */

module.exports = IdentityKey = (function() {
  function IdentityKey() {
    throw new DontCallConstructor(this);
  }

  IdentityKey["new"] = function(public_key) {
    var key;
    TypeUtil.assert_is_instance(PublicKey, public_key);
    key = ClassUtil.new_instance(IdentityKey);
    key.public_key = public_key;
    return key;
  };

  IdentityKey.prototype.fingerprint = function() {
    return this.public_key.fingerprint();
  };

  IdentityKey.prototype.toString = function() {
    return sodium.to_hex(this.public_key);
  };

  IdentityKey.prototype.encode = function(e) {
    e.object(1);
    e.u8(0);
    return this.public_key.encode(e);
  };

  IdentityKey.decode = function(d) {
    var i, nprops, public_key, ref;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    public_key = null;
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          public_key = PublicKey.decode(d);
          break;
        default:
          d.skip();
      }
    }
    return IdentityKey["new"](public_key);
  };

  return IdentityKey;

})();
