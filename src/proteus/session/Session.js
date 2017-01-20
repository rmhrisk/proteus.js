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

var CBOR, CipherMessage, ClassUtil, DecodeError, DecryptError, DontCallConstructor, Envelope,
    IdentityKey, IdentityKeyPair, KeyPair, PreKey, PreKeyBundle, PreKeyMessage, PreKeyStore,
    ProteusError, PublicKey, Session, SessionState, SessionTag, TypeUtil,
  bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
  indexOf = [].indexOf || function(item) { for (var i = 0, l = this.length; i < l; i++) { if (i in this && this[i] === item) return i; } return -1; };

CBOR = require('wire-webapp-cbor');
DontCallConstructor = require('../errors/DontCallConstructor');
ClassUtil = require('../util/ClassUtil');
TypeUtil = require('../util/TypeUtil');
ProteusError = require('../errors/ProteusError');
DecryptError = require('../errors/DecryptError');
DecodeError = require('../errors/DecodeError');
IdentityKeyPair = require('../keys/IdentityKeyPair');
IdentityKey = require('../keys/IdentityKey');
PreKeyBundle = require('../keys/PreKeyBundle');
PublicKey = require('../keys/PublicKey');
KeyPair = require('../keys/KeyPair');
PreKey = require('../keys/PreKey');
Envelope = require('../message/Envelope');
CipherMessage = require('../message/CipherMessage');
PreKeyMessage = require('../message/PreKeyMessage');
SessionTag = require('../message/SessionTag');
PreKeyStore = require('./PreKeyStore');

module.exports = Session = (function() {
  Session.MAX_RECV_CHAINS = 5;

  Session.MAX_SESSION_STATES = 100;

  function Session() {
    this._decrypt_prekey_message = bind(this._decrypt_prekey_message, this);
    this.counter = 0;
    this.local_identity = null;
    this.pending_prekey = null;
    this.remote_identity = null;
    this.session_states = null;
    this.session_tag = null;
    this.version = 1;
    throw new DontCallConstructor(this);
  }


  /*
   * @param local_identity [IdentityKeyPair] Alice's Identity Key Pair
   * @param remote_pkbundle [Proteus.keys.PreKeyBundle] Bob's Pre-Key Bundle
   */

  Session.init_from_prekey = function(local_identity, remote_pkbundle) {
    return new Promise((function(_this) {
      return function(resolve) {
        var alice_base, session, session_tag, state;
        TypeUtil.assert_is_instance(IdentityKeyPair, local_identity);
        TypeUtil.assert_is_instance(PreKeyBundle, remote_pkbundle);
        alice_base = KeyPair.new();
        state = SessionState.init_as_alice(local_identity, alice_base, remote_pkbundle);
        session_tag = SessionTag.new();
        session = ClassUtil.new_instance(Session);
        session.session_tag = session_tag;
        session.local_identity = local_identity;
        session.remote_identity = remote_pkbundle.identity_key;
        session.pending_prekey = [remote_pkbundle.prekey_id, alice_base.public_key];
        session.session_states = {};
        session._insert_session_state(session_tag, state);
        return resolve(session);
      };
    })(this));
  };

  Session.init_from_message = function(our_identity, prekey_store, envelope) {
    return new Promise((function(_this) {
      return function(resolve, reject) {
        var pkmsg, session;
        TypeUtil.assert_is_instance(IdentityKeyPair, our_identity);
        TypeUtil.assert_is_instance(PreKeyStore, prekey_store);
        TypeUtil.assert_is_instance(Envelope, envelope);
        pkmsg = (function() {
          switch (false) {
            case !(envelope.message instanceof CipherMessage):
              throw new DecryptError.InvalidMessage('Can\'t initialise a session from a CipherMessage.');
              break;
            case !(envelope.message instanceof PreKeyMessage):
              return envelope.message;
            default:
              throw new DecryptError.InvalidMessage;
          }
        })();
        session = ClassUtil.new_instance(Session);
        session.session_tag = pkmsg.message.session_tag;
        session.local_identity = our_identity;
        session.remote_identity = pkmsg.identity_key;
        session.pending_prekey = null;
        session.session_states = {};
        return session._new_state(prekey_store, pkmsg).then(function(state) {
          var plain;
          plain = state.decrypt(envelope, pkmsg.message);
          session._insert_session_state(pkmsg.message.session_tag, state);
          if (pkmsg.prekey_id < PreKey.MAX_PREKEY_ID) {
            return prekey_store.remove(pkmsg.prekey_id).then(function() {
              return resolve([session, plain]);
            }).catch(function(error) {
              return reject(new DecryptError.PrekeyNotFound('Could not delete PreKey: ' + error.message));
            });
          } else {
            return resolve([session, plain]);
          }
        }).catch(reject);
      };
    })(this));
  };

  Session.prototype._new_state = function(pre_key_store, pre_key_message) {
    return pre_key_store.get_prekey(pre_key_message.prekey_id).then((function(_this) {
      return function(pre_key) {
        if (pre_key) {
          return SessionState.init_as_bob(_this.local_identity, pre_key.key_pair, pre_key_message.identity_key, pre_key_message.base_key);
        }
        throw new ProteusError('Unable to get PreKey');
      };
    })(this));
  };

  Session.prototype._insert_session_state = function(tag, state) {
    var obj_size;
    if (indexOf.call(this.session_states, tag) >= 0) {
      this.session_states[tag].state = state;
    } else {
      if (this.counter >= Number.MAX_SAFE_INTEGER) {
        this.session_states = {};
        this.counter = 0;
      }
      this.session_states[tag] = {
        idx: this.counter,
        tag: tag,
        state: state
      };
      this.counter++;
    }
    if (this.session_tag.toString() !== tag.toString()) {
      this.session_tag = tag;
    }
    obj_size = function(obj) {
      return Object.keys(obj).length;
    };
    if (obj_size(this.session_states) < Session.MAX_SESSION_STATES) {
      return;
    }

    // if we get here, it means that we have more than MAX_SESSION_STATES and
    // we need to evict the oldest one.
    return this._evict_oldest_session_state();
  };

  Session.prototype._evict_oldest_session_state = function() {
    var k, oldest, reduction, states, v;
    states = (function() {
      var j, len, ref, results;
      ref = this.session_states;
      results = [];
      for (v = j = 0, len = ref.length; j < len; v = ++j) {
        k = ref[v];
        if (k.toString() !== this.session_tag.toString()) {
          results.push([k, v]);
        }
      }
      return results;
    }).call(this);
    reduction = function(accumulator, item) {
      var tag, val;
      tag = item[0];
      val = item[1];
      if (!accumulator || val.idx < accumulator.idx) {
        return {
          idx: val.idx,
          tag: k
        };
      }
      return accumulator;
    };
    oldest = states.reduce(reduction, null);
    return delete this.session_states[oldest.tag];
  };

  Session.prototype.get_local_identity = function() {
    return this.local_identity.public_key;
  };


  /*
   * @param plaintext [String, Uint8Array] The plaintext which needs to be encrypted
   * @return [Proteus.message.Envelope] Encrypted message
   */

  Session.prototype.encrypt = function(plaintext) {
    return new Promise((function(_this) {
      return function(resolve, reject) {
        var ref, state;
        state = _this.session_states[_this.session_tag];
        if (!state) {
          return reject(new ProteusError("Could not find session for tag '" + ((ref = _this.session_tag) != null ? ref.toString() : void 0) + "'."));
        }
        return resolve(state.state.encrypt(_this.local_identity.public_key, _this.pending_prekey, _this.session_tag, plaintext));
      };
    })(this));
  };

  Session.prototype.decrypt = function(prekey_store, envelope) {
    return new Promise((function(_this) {
      return function(resolve) {
        var msg;
        TypeUtil.assert_is_instance(PreKeyStore, prekey_store);
        TypeUtil.assert_is_instance(Envelope, envelope);
        msg = envelope.message;
        switch (false) {
          case !(msg instanceof CipherMessage):
            return resolve(_this._decrypt_cipher_message(envelope, envelope.message));
          case !(msg instanceof PreKeyMessage):
            if (msg.identity_key.fingerprint() !== _this.remote_identity.fingerprint()) {
              throw new DecryptError.RemoteIdentityChanged;
            }
            return resolve(_this._decrypt_prekey_message(envelope, msg, prekey_store));
          default:
            throw new DecryptError('Unknown message type.');
        }
      };
    })(this));
  };

  Session.prototype._decrypt_prekey_message = function(envelope, msg, prekey_store) {
    return Promise.resolve().then((function(_this) {
      return function() {
        return _this._decrypt_cipher_message(envelope, msg.message);
      };
    })(this)).catch((function(_this) {
      return function(error) {
        if (error instanceof DecryptError.InvalidSignature || error instanceof DecryptError.InvalidMessage) {
          return _this._new_state(prekey_store, msg).then(function(state) {
            var plaintext;
            plaintext = state.decrypt(envelope, msg.message);
            if (msg.prekey_id !== PreKey.MAX_PREKEY_ID) {
              prekey_store.remove(msg.prekey_id);
            }
            _this._insert_session_state(msg.message.session_tag, state);
            _this.pending_prekey = null;
            return plaintext;
          });
        }
        throw error;
      };
    })(this));
  };

  Session.prototype._decrypt_cipher_message = function(envelope, msg) {
    var plaintext, ref, state;
    state = this.session_states[msg.session_tag];
    if (!state) {
      throw new DecryptError.InvalidMessage("We received a message with session tag '" +
        ((ref = msg.session_tag) != null ? ref.toString() : void 0) + "', but we don't have a session for this tag.");
    }

    // serialise and de-serialise for a deep clone
    // THIS IS IMPORTANT, DO NOT MUTATE THE SESSION STATE IN-PLACE
    // mutating in-place can lead to undefined behavior and undefined state in edge cases
    state = SessionState.deserialise(state.state.serialise());
    plaintext = state.decrypt(envelope, msg);
    this.pending_prekey = null;
    this._insert_session_state(msg.session_tag, state);
    return plaintext;
  };

  Session.prototype.serialise = function() {
    var e;
    e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  };

  Session.deserialise = function(local_identity, buf) {
    var d;
    TypeUtil.assert_is_instance(IdentityKeyPair, local_identity);
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    d = new CBOR.Decoder(buf);
    return Session.decode(local_identity, d);
  };

  Session.prototype.encode = function(e) {
    var _, ref, results, state;
    e.object(6);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    this.session_tag.encode(e);
    e.u8(2);
    this.local_identity.public_key.encode(e);
    e.u8(3);
    this.remote_identity.encode(e);
    e.u8(4);
    if (this.pending_prekey) {
      e.object(2);
      e.u8(0);
      e.u16(this.pending_prekey[0]);
      e.u8(1);
      this.pending_prekey[1].encode(e);
    } else {
      e.null();
    }
    e.u8(5);
    e.object(Object.keys(this.session_states).length);
    ref = this.session_states;
    results = [];
    for (_ in ref) {
      state = ref[_];
      state.tag.encode(e);
      results.push(state.state.encode(e));
    }
    return results;
  };

  Session.decode = function(local_identity, d) {
    var _, i, ik, j, l, m, nprops, ref, ref1, self, tag;
    TypeUtil.assert_is_instance(IdentityKeyPair, local_identity);
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(Session);
    nprops = d.object();
    for (j = 0, ref = nprops - 1; 0 <= ref ? j <= ref : j >= ref; 0 <= ref ? j++ : j--) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.session_tag = SessionTag.decode(d);
          break;
        case 2:
          ik = IdentityKey.decode(d);
          if (local_identity.public_key.fingerprint() !== ik.fingerprint()) {
            throw new DecodeError.LocalIdentityChanged;
          }
          self.local_identity = local_identity;
          break;
        case 3:
          self.remote_identity = IdentityKey.decode(d);
          break;
        case 4:
          switch (d.optional(function() {
                return d.object();
              })) {
            case null:
              self.pending_prekey = null;
              break;
            case 2:
              self.pending_prekey = [null, null];
              for (_ = l = 0; l <= 1; _ = ++l) {
                switch (d.u8()) {
                  case 0:
                    self.pending_prekey[0] = d.u16();
                    break;
                  case 1:
                    self.pending_prekey[1] = PublicKey.decode(d);
                }
              }
              break;
            default:
              throw new DecodeError.InvalidType;
          }
          break;
        case 5:
          self.session_states = {};
          for (i = m = 0, ref1 = d.object() - 1; 0 <= ref1 ? m <= ref1 : m >= ref1; i = 0 <= ref1 ? ++m : --m) {
            tag = SessionTag.decode(d);
            self.session_states[tag] = {
              idx: i,
              tag: tag,
              state: SessionState.decode(d)
            };
          }
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_instance(SessionTag, self.session_tag);
    TypeUtil.assert_is_instance(IdentityKeyPair, self.local_identity);
    TypeUtil.assert_is_instance(IdentityKey, self.remote_identity);
    TypeUtil.assert_is_instance(Object, self.session_states);
    return self;
  };

  return Session;

})();

SessionState = require('./SessionState');
