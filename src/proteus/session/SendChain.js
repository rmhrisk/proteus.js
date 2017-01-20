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

var CBOR, ChainKey, ClassUtil, DontCallConstructor, KeyPair, SendChain, TypeUtil;

CBOR = require('wire-webapp-cbor');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

KeyPair = require('../keys/KeyPair');

ChainKey = require('./ChainKey');

module.exports = SendChain = (function() {
  function SendChain() {
    throw new DontCallConstructor(this);
  }

  SendChain["new"] = function(chain_key, keypair) {
    var sc;
    TypeUtil.assert_is_instance(ChainKey, chain_key);
    TypeUtil.assert_is_instance(KeyPair, keypair);
    sc = ClassUtil.new_instance(SendChain);
    sc.chain_key = chain_key;
    sc.ratchet_key = keypair;
    return sc;
  };

  SendChain.prototype.encode = function(e) {
    e.object(2);
    e.u8(0);
    this.chain_key.encode(e);
    e.u8(1);
    return this.ratchet_key.encode(e);
  };

  SendChain.decode = function(d) {
    var i, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(SendChain);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.chain_key = ChainKey.decode(d);
          break;
        case 1:
          self.ratchet_key = KeyPair.decode(d);
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(ChainKey, self.chain_key);
    TypeUtil.assert_is_instance(KeyPair, self.ratchet_key);
    return self;
  };

  return SendChain;

})();
