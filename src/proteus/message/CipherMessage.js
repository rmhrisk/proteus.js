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

var CBOR, CipherMessage, ClassUtil, DontCallConstructor, Message, PublicKey, SessionTag, TypeUtil,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

CBOR = require('wire-webapp-cbor');
DontCallConstructor = require('../errors/DontCallConstructor');
ClassUtil = require('../util/ClassUtil');
TypeUtil = require('../util/TypeUtil');
PublicKey = require('../keys/PublicKey');
Message = require('./Message');
SessionTag = require('./SessionTag');

module.exports = CipherMessage = (function(superClass) {
  extend(CipherMessage, superClass);

  function CipherMessage() {
    throw new DontCallConstructor(this);
  }

  CipherMessage.new = function(session_tag, counter, prev_counter, ratchet_key, cipher_text) {
    var cm;
    TypeUtil.assert_is_instance(SessionTag, session_tag);
    TypeUtil.assert_is_integer(counter);
    TypeUtil.assert_is_integer(prev_counter);
    TypeUtil.assert_is_instance(PublicKey, ratchet_key);
    TypeUtil.assert_is_instance(Uint8Array, cipher_text);
    cm = ClassUtil.new_instance(CipherMessage);
    cm.session_tag = session_tag;
    cm.counter = counter;
    cm.prev_counter = prev_counter;
    cm.ratchet_key = ratchet_key;
    cm.cipher_text = cipher_text;
    Object.freeze(cm);
    return cm;
  };

  CipherMessage.prototype.encode = function(e) {
    e.object(5);
    e.u8(0);
    this.session_tag.encode(e);
    e.u8(1);
    e.u32(this.counter);
    e.u8(2);
    e.u32(this.prev_counter);
    e.u8(3);
    this.ratchet_key.encode(e);
    e.u8(4);
    return e.bytes(this.cipher_text);
  };

  CipherMessage.decode = function(d) {
    var cipher_text, counter, i, nprops, prev_counter, ratchet_key, ref, session_tag;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    session_tag = null;
    counter = null;
    prev_counter = null;
    ratchet_key = null;
    cipher_text = null;
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          session_tag = SessionTag.decode(d);
          break;
        case 1:
          counter = d.u32();
          break;
        case 2:
          prev_counter = d.u32();
          break;
        case 3:
          ratchet_key = PublicKey.decode(d);
          break;
        case 4:
          cipher_text = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    return CipherMessage.new(session_tag, counter, prev_counter, ratchet_key, cipher_text);
  };

  return CipherMessage;

})(Message);
