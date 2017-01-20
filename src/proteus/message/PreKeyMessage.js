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

var CBOR, CipherMessage, ClassUtil, DontCallConstructor, IdentityKey, Message, PreKeyMessage, PublicKey, TypeUtil,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

CBOR = require('wire-webapp-cbor');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

PublicKey = require('../keys/PublicKey');

IdentityKey = require('../keys/IdentityKey');

Message = require('./Message');

CipherMessage = require('./CipherMessage');

module.exports = PreKeyMessage = (function(superClass) {
  extend(PreKeyMessage, superClass);

  function PreKeyMessage() {
    throw new DontCallConstructor(this);
  }

  PreKeyMessage["new"] = function(prekey_id, base_key, identity_key, message) {
    var pkm;
    TypeUtil.assert_is_integer(prekey_id);
    TypeUtil.assert_is_instance(PublicKey, base_key);
    TypeUtil.assert_is_instance(IdentityKey, identity_key);
    TypeUtil.assert_is_instance(CipherMessage, message);
    pkm = ClassUtil.new_instance(PreKeyMessage);
    pkm.prekey_id = prekey_id;
    pkm.base_key = base_key;
    pkm.identity_key = identity_key;
    pkm.message = message;
    Object.freeze(pkm);
    return pkm;
  };

  PreKeyMessage.prototype.encode = function(e) {
    e.object(4);
    e.u8(0);
    e.u16(this.prekey_id);
    e.u8(1);
    this.base_key.encode(e);
    e.u8(2);
    this.identity_key.encode(e);
    e.u8(3);
    return this.message.encode(e);
  };

  PreKeyMessage.decode = function(d) {
    var base_key, i, identity_key, message, nprops, prekey_id, ref;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    prekey_id = null;
    base_key = null;
    identity_key = null;
    message = null;
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          prekey_id = d.u16();
          break;
        case 1:
          base_key = PublicKey.decode(d);
          break;
        case 2:
          identity_key = IdentityKey.decode(d);
          break;
        case 3:
          message = CipherMessage.decode(d);
          break;
        default:
          d.skip();
      }
    }

    // checks for missing variables happens in constructor
    return PreKeyMessage["new"](prekey_id, base_key, identity_key, message);
  };

  return PreKeyMessage;

})(Message);
