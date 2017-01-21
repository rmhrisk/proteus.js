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

const DontCallConstructor = require('../errors/DontCallConstructor');
const ClassUtil = require('../util/ClassUtil');
const TypeUtil = require('../util/TypeUtil');

const KeyPair = require('../keys/KeyPair');

const ChainKey = require('./ChainKey');

module.exports = class SendChain {
  constructor () {
    throw new DontCallConstructor(this);
  }

  static new (chain_key, keypair) {
    TypeUtil.assert_is_instance(ChainKey, chain_key);
    TypeUtil.assert_is_instance(KeyPair, keypair);

    const sc = ClassUtil.new_instance(SendChain);
    sc.chain_key = chain_key;
    sc.ratchet_key = keypair;
    return sc;
  };

  encode (e) {
    e.object(2);
    e.u8(0);
    this.chain_key.encode(e);
    e.u8(1);
    return this.ratchet_key.encode(e);
  };

  static decode (d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    const self = ClassUtil.new_instance(SendChain);
    const nprops = d.object();
    for (let i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
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
};
