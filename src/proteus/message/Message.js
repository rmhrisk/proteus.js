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

var CBOR, CipherMessage, DecodeError, DontCallConstructor, Message, PreKeyMessage, TypeUtil;

CBOR = require('wire-webapp-cbor');
DontCallConstructor = require('../errors/DontCallConstructor');
TypeUtil = require('../util/TypeUtil');
DecodeError = require('../errors/DecodeError');

module.exports = Message = (function() {
  function Message() {
    throw new DontCallConstructor(this);
  }

  Message.prototype.serialise = function() {
    var e;
    e = new CBOR.Encoder();
    switch (false) {
      case !(this instanceof CipherMessage):
        e.u8(1);
        break;
      case !(this instanceof PreKeyMessage):
        e.u8(2);
        break;
      default:
        throw new TypeError('Unexpected message type');
    }
    this.encode(e);
    return e.get_buffer();
  };

  Message.deserialise = function(buf) {
    var d;
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    d = new CBOR.Decoder(buf);
    switch (d.u8()) {
      case 1:
        return CipherMessage.decode(d);
      case 2:
        return PreKeyMessage.decode(d);
      default:
        throw new DecodeError.InvalidType('Unrecognised message type');
    }
  };

  return Message;

})();


// these require lines have to come after the Message definition because otherwise
// it creates a circular dependency with the message subtypes

CipherMessage = require('./CipherMessage');

PreKeyMessage = require('./PreKeyMessage');
