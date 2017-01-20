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

var CBOR, ChainKey, CipherMessage, ClassUtil, DecryptError, DontCallConstructor, Envelope, MessageKeys, ProteusError, PublicKey, RecvChain, TypeUtil;

CBOR = require('wire-webapp-cbor');

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

TypeUtil = require('../util/TypeUtil');

PublicKey = require('../keys/PublicKey');

ProteusError = require('../errors/ProteusError');

DecryptError = require('../errors/DecryptError');

Envelope = require('../message/Envelope');

CipherMessage = require('../message/CipherMessage');

MessageKeys = require('./MessageKeys');

ChainKey = require('./ChainKey');

module.exports = RecvChain = (function() {
  RecvChain.MAX_COUNTER_GAP = 1000;

  function RecvChain() {
    throw new DontCallConstructor(this);
  }

  RecvChain["new"] = function(chain_key, public_key) {
    var rc;
    TypeUtil.assert_is_instance(ChainKey, chain_key);
    TypeUtil.assert_is_instance(PublicKey, public_key);
    rc = ClassUtil.new_instance(RecvChain);
    rc.chain_key = chain_key;
    rc.ratchet_key = public_key;
    rc.message_keys = [];
    return rc;
  };

  RecvChain.prototype.try_message_keys = function(envelope, msg) {
    var idx, mk;
    TypeUtil.assert_is_instance(Envelope, envelope);
    TypeUtil.assert_is_instance(CipherMessage, msg);
    if (this.message_keys[0] && this.message_keys[0].counter > msg.counter) {
      throw new DecryptError.OutdatedMessage;
    }
    idx = this.message_keys.findIndex(function(mk) {
      return mk.counter === msg.counter;
    });
    if (idx === -1) {
      throw new DecryptError.DuplicateMessage;
    }
    mk = this.message_keys.splice(idx, 1)[0];
    if (!envelope.verify(mk.mac_key)) {
      throw new DecryptError.InvalidSignature;
    }
    return mk.decrypt(msg.cipher_text);
  };

  RecvChain.prototype.stage_message_keys = function(msg) {
    var _, chk, i, keys, mk, num, ref;
    TypeUtil.assert_is_instance(CipherMessage, msg);
    num = msg.counter - this.chain_key.idx;
    if (num > RecvChain.MAX_COUNTER_GAP) {
      throw new DecryptError.TooDistantFuture;
    }
    keys = [];
    chk = this.chain_key;
    for (_ = i = 0, ref = num - 1; 0 <= ref ? i <= ref : i >= ref; _ = 0 <= ref ? ++i : --i) {
      keys.push(chk.message_keys());
      chk = chk.next();
    }
    mk = chk.message_keys();
    return [chk, mk, keys];
  };

  RecvChain.prototype.commit_message_keys = function(keys) {
    var _, excess, i, ref;
    TypeUtil.assert_is_instance(Array, keys);
    keys.map(function(k) {
      return TypeUtil.assert_is_instance(MessageKeys, k);
    });
    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError('More keys than MAX_COUNTER_GAP');
    }
    excess = this.message_keys.length + keys.length - RecvChain.MAX_COUNTER_GAP;
    for (_ = i = 0, ref = excess - 1; 0 <= ref ? i <= ref : i >= ref; _ = 0 <= ref ? ++i : --i) {
      this.message_keys.shift();
    }
    keys.map((function(_this) {
      return function(k) {
        return _this.message_keys.push(k);
      };
    })(this));
    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError('Skipped keys greater than MAX_COUNTER_GAP');
    }
  };

  RecvChain.prototype.encode = function(e) {
    e.object(3);
    e.u8(0);
    this.chain_key.encode(e);
    e.u8(1);
    this.ratchet_key.encode(e);
    e.u8(2);
    e.array(this.message_keys.length);
    return this.message_keys.map(function(k) {
      return k.encode(e);
    });
  };

  RecvChain.decode = function(d) {
    var i, len, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(RecvChain);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.chain_key = ChainKey.decode(d);
          break;
        case 1:
          self.ratchet_key = PublicKey.decode(d);
          break;
        case 2:
          self.message_keys = [];
          len = d.array();
          while (len--) {
            self.message_keys.push(MessageKeys.decode(d));
          }
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(ChainKey, self.chain_key);
    TypeUtil.assert_is_instance(PublicKey, self.ratchet_key);
    TypeUtil.assert_is_instance(Array, self.message_keys);
    return self;
  };

  return RecvChain;

})();
