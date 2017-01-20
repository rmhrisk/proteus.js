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

var ArrayUtil, CBOR, ChainKey, CipherMessage, ClassUtil, DecryptError, DerivedSecrets,
    DontCallConstructor, Envelope, IdentityKey, IdentityKeyPair, KeyPair, PreKeyBundle,
    PreKeyMessage, PublicKey, RecvChain, RootKey, SendChain, Session, SessionState, SessionTag,
    TypeUtil;

CBOR = require('wire-webapp-cbor');
DontCallConstructor = require('../errors/DontCallConstructor');
ClassUtil = require('../util/ClassUtil');
TypeUtil = require('../util/TypeUtil');
ArrayUtil = require('../util/ArrayUtil');
DecryptError = require('../errors/DecryptError');
DerivedSecrets = require('../derived/DerivedSecrets');
IdentityKeyPair = require('../keys/IdentityKeyPair');
IdentityKey = require('../keys/IdentityKey');
PreKeyBundle = require('../keys/PreKeyBundle');
PublicKey = require('../keys/PublicKey');
KeyPair = require('../keys/KeyPair');
Envelope = require('../message/Envelope');
CipherMessage = require('../message/CipherMessage');
PreKeyMessage = require('../message/PreKeyMessage');
SessionTag = require('../message/SessionTag');
RecvChain = require('./RecvChain');
SendChain = require('./SendChain');
ChainKey = require('./ChainKey');
RootKey = require('./RootKey');
Session = require('./Session');

module.exports = SessionState = (function() {
  function SessionState() {
    this.recv_chains = null;
    this.send_chain = null;
    this.root_key = null;
    this.prev_counter = null;
    throw new DontCallConstructor(this);
  }

  SessionState.init_as_alice = function(alice_identity_pair, alice_base, bob_pkbundle) {
    var chainkey, chk, dsecs, master_key, recv_chains, ref, rok, rootkey, send_chain, send_ratchet, state;
    TypeUtil.assert_is_instance(IdentityKeyPair, alice_identity_pair);
    TypeUtil.assert_is_instance(KeyPair, alice_base);
    TypeUtil.assert_is_instance(PreKeyBundle, bob_pkbundle);
    master_key = ArrayUtil.concatenate_array_buffers([
      alice_identity_pair.secret_key.shared_secret(bob_pkbundle.public_key),
      alice_base.secret_key.shared_secret(bob_pkbundle.identity_key.public_key),
      alice_base.secret_key.shared_secret(bob_pkbundle.public_key)
    ]);
    dsecs = DerivedSecrets.kdf_without_salt(master_key, 'handshake');
    rootkey = RootKey.from_cipher_key(dsecs.cipher_key);
    chainkey = ChainKey.from_mac_key(dsecs.mac_key, 0);
    recv_chains = [RecvChain.new(chainkey, bob_pkbundle.public_key)];
    send_ratchet = KeyPair.new();
    ref = rootkey.dh_ratchet(send_ratchet, bob_pkbundle.public_key), rok = ref[0], chk = ref[1];
    send_chain = SendChain.new(chk, send_ratchet);
    state = ClassUtil.new_instance(SessionState);
    state.recv_chains = recv_chains;
    state.send_chain = send_chain;
    state.root_key = rok;
    state.prev_counter = 0;
    return state;
  };

  SessionState.init_as_bob = function(bob_ident, bob_prekey, alice_ident, alice_base) {
    var chainkey, dsecs, master_key, rootkey, send_chain, state;
    TypeUtil.assert_is_instance(IdentityKeyPair, bob_ident);
    TypeUtil.assert_is_instance(KeyPair, bob_prekey);
    TypeUtil.assert_is_instance(IdentityKey, alice_ident);
    TypeUtil.assert_is_instance(PublicKey, alice_base);
    master_key = ArrayUtil.concatenate_array_buffers([
      bob_prekey.secret_key.shared_secret(alice_ident.public_key),
      bob_ident.secret_key.shared_secret(alice_base),
      bob_prekey.secret_key.shared_secret(alice_base)
    ]);
    dsecs = DerivedSecrets.kdf_without_salt(master_key, 'handshake');
    rootkey = RootKey.from_cipher_key(dsecs.cipher_key);
    chainkey = ChainKey.from_mac_key(dsecs.mac_key, 0);
    send_chain = SendChain.new(chainkey, bob_prekey);
    state = ClassUtil.new_instance(SessionState);
    state.recv_chains = [];
    state.send_chain = send_chain;
    state.root_key = rootkey;
    state.prev_counter = 0;
    return state;
  };

  SessionState.prototype.ratchet = function(ratchet_key) {
    var new_ratchet, recv_chain, recv_chain_key, recv_root_key, ref, ref1, send_chain,
        send_chain_key, send_root_key;
    new_ratchet = KeyPair.new();
    ref = this.root_key.dh_ratchet(this.send_chain.ratchet_key, ratchet_key), recv_root_key = ref[0], recv_chain_key = ref[1];
    ref1 = recv_root_key.dh_ratchet(new_ratchet, ratchet_key), send_root_key = ref1[0], send_chain_key = ref1[1];
    recv_chain = RecvChain.new(recv_chain_key, ratchet_key);
    send_chain = SendChain.new(send_chain_key, new_ratchet);
    this.root_key = send_root_key;
    this.prev_counter = this.send_chain.chain_key.idx;
    this.send_chain = send_chain;
    this.recv_chains.unshift(recv_chain);
    if (this.recv_chains.length > Session.MAX_RECV_CHAINS) {
      this.recv_chains = this.recv_chains.slice(0, Session.MAX_RECV_CHAINS);
    }
  };


  /*
   * @param identity_key [Proteus.keys.IdentityKey] Public identity key of the local identity key pair
   * @param pending [] Pending pre-key
   * @param tag [Proteus.message.SessionTag] Session tag
   * @param plaintext [String, Uint8Array] The plaintext to encrypt
   *
   * @return [Proteus.message.Envelope]
   */

  SessionState.prototype.encrypt = function(identity_key, pending, tag, plaintext) {
    var env, message, msgkeys;
    if (pending) {
      TypeUtil.assert_is_integer(pending[0]);
      TypeUtil.assert_is_instance(PublicKey, pending[1]);
    }
    TypeUtil.assert_is_instance(IdentityKey, identity_key);
    TypeUtil.assert_is_instance(SessionTag, tag);
    msgkeys = this.send_chain.chain_key.message_keys();
    message = CipherMessage.new(tag, this.send_chain.chain_key.idx, this.prev_counter, this.send_chain.ratchet_key.public_key, msgkeys.encrypt(plaintext));
    if (pending) {
      message = PreKeyMessage.new(pending[0], pending[1], identity_key, message);
    }
    env = Envelope.new(msgkeys.mac_key, message);
    this.send_chain.chain_key = this.send_chain.chain_key.next();
    return env;
  };

  SessionState.prototype.decrypt = function(envelope, msg) {
    var chk, idx, mk, mks, plain, rc, ref;
    TypeUtil.assert_is_instance(Envelope, envelope);
    TypeUtil.assert_is_instance(CipherMessage, msg);
    idx = this.recv_chains.findIndex(function(c) {
      return c.ratchet_key.fingerprint() === msg.ratchet_key.fingerprint();
    });
    if (idx === -1) {
      this.ratchet(msg.ratchet_key);
      idx = 0;
    }
    rc = this.recv_chains[idx];
    switch (false) {
      case !(msg.counter < rc.chain_key.idx):
        return rc.try_message_keys(envelope, msg);
      case msg.counter !== rc.chain_key.idx:
        mks = rc.chain_key.message_keys();
        if (!envelope.verify(mks.mac_key)) {
          throw new DecryptError.InvalidSignature;
        }
        plain = mks.decrypt(msg.cipher_text);
        rc.chain_key = rc.chain_key.next();
        return plain;
      case !(msg.counter > rc.chain_key.idx):
        ref = rc.stage_message_keys(msg), chk = ref[0], mk = ref[1], mks = ref[2];
        if (!envelope.verify(mk.mac_key)) {
          throw new DecryptError.InvalidSignature;
        }
        plain = mk.decrypt(msg.cipher_text);
        rc.chain_key = chk.next();
        rc.commit_message_keys(mks);
        return plain;
    }
  };

  SessionState.prototype.serialise = function() {
    var e;
    e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  };

  SessionState.deserialise = function(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return SessionState.decode(new CBOR.Decoder(buf));
  };

  SessionState.prototype.encode = function(e) {
    e.object(4);
    e.u8(0);
    e.array(this.recv_chains.length);
    this.recv_chains.map(function(rch) {
      return rch.encode(e);
    });
    e.u8(1);
    this.send_chain.encode(e);
    e.u8(2);
    this.root_key.encode(e);
    e.u8(3);
    return e.u32(this.prev_counter);
  };

  SessionState.decode = function(d) {
    var i, len, nprops, ref, self;
    TypeUtil.assert_is_instance(CBOR.Decoder, d);
    self = ClassUtil.new_instance(SessionState);
    nprops = d.object();
    for (i = 0, ref = nprops - 1; 0 <= ref ? i <= ref : i >= ref; 0 <= ref ? i++ : i--) {
      switch (d.u8()) {
        case 0:
          self.recv_chains = [];
          len = d.array();
          while (len--) {
            self.recv_chains.push(RecvChain.decode(d));
          }
          break;
        case 1:
          self.send_chain = SendChain.decode(d);
          break;
        case 2:
          self.root_key = RootKey.decode(d);
          break;
        case 3:
          self.prev_counter = d.u32();
          break;
        default:
          d.skip();
      }
    }
    TypeUtil.assert_is_instance(Array, self.recv_chains);
    TypeUtil.assert_is_instance(SendChain, self.send_chain);
    TypeUtil.assert_is_instance(RootKey, self.root_key);
    TypeUtil.assert_is_integer(self.prev_counter);
    return self;
  };

  return SessionState;

})();
