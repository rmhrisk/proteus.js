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

var CBOR, ClassUtil, DontCallConstructor, Envelope, MacKey, Message, TypeUtil;

CBOR = require('wire-webapp-cbor');
DontCallConstructor = require('../errors/DontCallConstructor');
ClassUtil = require('../util/ClassUtil');
TypeUtil = require('../util/TypeUtil');
MacKey = require('../derived/MacKey');
Message = require('./Message');

module.exports = Envelope = (function() {
  function Envelope() {
    throw new DontCallConstructor(this);
  }

  Envelope.new = function(mac_key, message) {
    var env, message_enc;
    TypeUtil.assert_is_instance(MacKey, mac_key);
    TypeUtil.assert_is_instance(Message, message);
    message_enc = new Uint8Array(message.serialise());
    env = ClassUtil.new_instance(Envelope);
    env.version = 1;
    env.mac = mac_key.sign(message_enc);
    env.message = message;
    env._message_enc = message_enc;
    Object.freeze(env);
    return env;
  };

  Envelope.prototype.verify = function(mac_key) {
    TypeUtil.assert_is_instance(MacKey, mac_key);
    return mac_key.verify(this.mac, this._message_enc);
  };


  /*
   * @return [ArrayBuffer] The serialized message envelope
   */

  Envelope.prototype.serialise = function() {
    var e;
    e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  };

  Envelope.deserialise = function(buf) {
    var d;
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    d = new CBOR.Decoder(buf);
    return Envelope.decode(d);
  };

  Envelope.prototype.encode = function(e) {
    e.object(3);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    e.object(1);
    e.u8(0);
    e.bytes(this.mac);
    e.u8(2);
    return e.bytes(this._message_enc);
  };

  Envelope.decode = function(d) {
    var env, i, j, nprops, nprops_mac, ref, ref1;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    env = ClassUtil.new_instance(Envelope);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          env.version = d.u8();
          break;
        case 1:
          nprops_mac = d.object();
          for (j = 0, ref1 = nprops_mac - 1; 0 <= ref1 ? j <= ref1 : j >= ref1; 0 <= ref1 ? j++ : j--) {
            switch (d.u8()) {
              case 0:
                env.mac = new Uint8Array(d.bytes());
                break;
              default:
                d.skip();
            }
          }
          break;
        case 2:
          env._message_enc = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_integer(env.version);
    TypeUtil.assert_is_instance(Uint8Array, env.mac);
    env.message = Message.deserialise(env._message_enc.buffer);
    Object.freeze(env);
    return env;
  };

  return Envelope;

})();
