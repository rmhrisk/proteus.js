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

var TestStore, assert_decrypt, assert_init_from_message, assert_prev_count, assert_serialise_deserialise,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

TestStore = (function(superClass) {
  extend(TestStore, superClass);

  function TestStore(prekeys) {
    this.prekeys = prekeys;
  }

  TestStore.prototype.get_prekey = function(prekey_id) {
    return new Promise((function(_this) {
      return function(resolve, reject) {
        return resolve(_this.prekeys[prekey_id]);
      };
    })(this));
  };

  TestStore.prototype.remove = function(prekey_id) {
    return new Promise((function(_this) {
      return function(resolve, reject) {
        delete _this.prekeys[prekey_id];
        return resolve();
      };
    })(this));
  };

  return TestStore;

})(Proteus.session.PreKeyStore);

assert_init_from_message = function(ident, store, msg, expected) {
  return new Promise(function(resolve, reject) {
    return Proteus.session.Session.init_from_message(ident, store, msg).then(function(x) {
      var s;
      s = x[0], msg = x[1];
      assert.strictEqual(sodium.to_string(msg), expected);
      return resolve(s);
    })["catch"](function(e) {
      return reject(e);
    });
  });
};

assert_decrypt = function(expected, p) {
  return new Promise(function(resolve, reject) {
    return p.then(function(actual) {
      assert.strictEqual(expected, sodium.to_string(actual));
      return resolve();
    })["catch"](function(e) {
      return reject(e);
    });
  });
};

assert_prev_count = function(session, expected) {
  return assert.strictEqual(expected, session.session_states[session.session_tag].state.prev_counter);
};

assert_serialise_deserialise = function(local_identity, session) {
  var bytes, deser, deser_bytes;
  bytes = session.serialise();
  deser = Proteus.session.Session.deserialise(local_identity, bytes);
  deser_bytes = deser.serialise();
  return assert.deepEqual(sodium.to_hex(new Uint8Array(bytes)), sodium.to_hex(new Uint8Array(deser_bytes)));
};

describe('Session', function() {
  it('can be serialised and deserialised to/from CBOR', function() {
    var alice_ident, alice_store, bob_bundle, bob_ident, bob_prekey, bob_store, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(alice) {
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);
      return assert_serialise_deserialise(alice_ident, alice);
    });
  });
  it('encrypts and decrypts messages', function(done) {
    var alice, alice_ident, alice_store, bob, bob_bundle, bob_ident, bob_prekey, bob_store, hello_alice, hello_bob, hello_bob_delayed, ping_bob_1, ping_bob_2, pong_alice, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    hello_bob = null;
    hello_bob_delayed = null;
    hello_alice = null;
    ping_bob_1 = null;
    ping_bob_2 = null;
    pong_alice = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);
      return Promise.all(['Hello Bob!', 'Hello delay!'].map(function(x) {
        return alice.encrypt(x);
      }));
    }).then(function(msgs) {
      hello_bob = msgs[0], hello_bob_delayed = msgs[1];
      assert(Object.keys(alice.session_states).length === 1);
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    }).then(function(s) {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 1);
      return bob.encrypt('Hello Alice!');
    }).then(function(m) {
      hello_alice = m;
      return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice));
    }).then(function() {
      assert(alice.pending_prekey === null);
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 2);
      assert(alice.remote_identity.fingerprint() === bob.local_identity.public_key.fingerprint());
      return Promise.all(['Ping1!', 'Ping2!'].map(function(x) {
        return alice.encrypt(x);
      }));
    }).then(function(msgs) {
      ping_bob_1 = msgs[0], ping_bob_2 = msgs[1];
      assert_prev_count(alice, 2);
      assert(ping_bob_1.message instanceof Proteus.message.CipherMessage);
      assert(ping_bob_2.message instanceof Proteus.message.CipherMessage);
      return assert_decrypt('Ping1!', bob.decrypt(bob_store, ping_bob_1));
    }).then(function() {
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 2);
      return assert_decrypt('Ping2!', bob.decrypt(bob_store, ping_bob_2));
    }).then(function() {
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 2);
      return bob.encrypt('Pong!');
    }).then(function(m) {
      pong_alice = m;
      assert_prev_count(bob, 1);
      return assert_decrypt('Pong!', alice.decrypt(alice_store, pong_alice));
    }).then(function() {
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 3);
      assert_prev_count(alice, 2);
      return assert_decrypt('Hello delay!', bob.decrypt(bob_store, hello_bob_delayed));
    }).then(function() {
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 2);
      assert_prev_count(bob, 1);
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('should limit the number of receive chains', function(done) {
    var alice, alice_ident, alice_store, bob, bob_bundle, bob_ident, bob_prekey, bob_store, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob!');
    }).then(function(hello_bob) {
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    }).then(function(s) {
      var j, ref2, results;
      bob = s;
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 1);
      return Promise.all((function() {
        results = [];
        for (var j = 0, ref2 = Proteus.session.Session.MAX_RECV_CHAINS * 2; 0 <= ref2 ? j <= ref2 : j >= ref2; 0 <= ref2 ? j++ : j--){ results.push(j); }
        return results;
      }).apply(this).map(function() {
        return new Promise(function(resolve, reject) {
          return bob.encrypt('ping').then(function(m) {
            return assert_decrypt('ping', alice.decrypt(alice_store, m));
          }).then(function() {
            return alice.encrypt('pong');
          }).then(function(m) {
            return assert_decrypt('pong', bob.decrypt(bob_store, m));
          }).then(function() {
            assert.isAtMost(alice.session_states[alice.session_tag].state.recv_chains.length, Proteus.session.Session.MAX_RECV_CHAINS);
            assert.isAtMost(bob.session_states[bob.session_tag].state.recv_chains.length, Proteus.session.Session.MAX_RECV_CHAINS);
            return resolve();
          });
        });
      }));
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('should handle a counter mismatch', function(done) {
    var alice, alice_ident, alice_store, bob, bob_bundle, bob_ident, bob_prekey, bob_store, ciphertexts, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    ciphertexts = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob!');
    }).then(function(m) {
      return assert_init_from_message(bob_ident, bob_store, m, 'Hello Bob!');
    }).then(function(s) {
      bob = s;
      return Promise.all(['Hello1', 'Hello2', 'Hello3', 'Hello4', 'Hello5'].map(function(x) {
        return bob.encrypt(x);
      }));
    }).then(function(t) {
      ciphertexts = t;
      return assert_decrypt('Hello2', alice.decrypt(alice_store, ciphertexts[1]));
    }).then(function() {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 1);
      assert_serialise_deserialise(alice_ident, alice);
      return assert_decrypt('Hello1', alice.decrypt(alice_store, ciphertexts[0]));
    }).then(function() {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 0);
      return assert_decrypt('Hello3', alice.decrypt(alice_store, ciphertexts[2]));
    }).then(function() {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 0);
      return assert_decrypt('Hello5', alice.decrypt(alice_store, ciphertexts[4]));
    }).then(function() {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 1);
      return assert_decrypt('Hello4', alice.decrypt(alice_store, ciphertexts[3]));
    }).then(function() {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 0);
      return Promise.all(ciphertexts.map(function(x) {
        return new Promise(function(resolve, reject) {
          return alice.decrypt(alice_store, x).then(function() {
            return assert.fail('should have raised Proteus.errors.DecryptError.DuplicateMessage');
          })["catch"](function(e) {
            assert.instanceOf(e, Proteus.errors.DecryptError.DuplicateMessage);
            return resolve();
          });
        });
      }));
    }).then(function() {
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('should handle multiple prekey messages', function(done) {
    var alice, alice_ident, bob, bob_bundle, bob_ident, bob_prekey, bob_store, hello_bob1, hello_bob2, hello_bob3, ref;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    hello_bob1 = null;
    hello_bob2 = null;
    hello_bob3 = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return Promise.all(['Hello Bob1!', 'Hello Bob2!', 'Hello Bob3!'].map(function(x) {
        return alice.encrypt(x);
      }));
    }).then(function(m) {
      hello_bob1 = m[0], hello_bob2 = m[1], hello_bob3 = m[2];
      return assert_init_from_message(bob_ident, bob_store, hello_bob1, 'Hello Bob1!');
    }).then(function(s) {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);
      return assert_decrypt('Hello Bob2!', bob.decrypt(bob_store, hello_bob2));
    }).then(function() {
      assert(Object.keys(bob.session_states).length === 1);
      return assert_decrypt('Hello Bob3!', bob.decrypt(bob_store, hello_bob3));
    }).then(function() {
      assert(Object.keys(bob.session_states).length === 1);
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('should handle simultaneous prekey messages', function(done) {
    var alice, alice_bundle, alice_ident, alice_prekey, alice_store, bob, bob_bundle, bob_ident, bob_prekey, bob_store, hello_alice, hello_bob, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice_prekey = alice_store.prekeys[0];
    alice_bundle = Proteus.keys.PreKeyBundle["new"](alice_ident.public_key, alice_prekey);
    alice = null;
    bob = null;
    hello_bob = null;
    hello_alice = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob!');
    }).then(function(m) {
      hello_bob = m;
      return bob = Proteus.session.Session.init_from_prekey(bob_ident, alice_bundle);
    }).then(function(s) {
      bob = s;
      return bob.encrypt('Hello Alice!');
    }).then(function(m) {
      hello_alice = m;
      assert.notStrictEqual(alice.session_tag.toString(), bob.session_tag.toString());
      return assert_decrypt('Hello Bob!', bob.decrypt(bob_store, hello_bob));
    }).then(function() {
      assert(Object.keys(bob.session_states).length === 2);
      return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice));
    }).then(function() {
      assert(Object.keys(alice.session_states).length === 2);
      return alice.encrypt('That was fast!');
    }).then(function(m) {
      assert_decrypt('That was fast!', bob.decrypt(bob_store, m));
      return bob.encrypt(':-)');
    }).then(function(m) {
      assert_decrypt(':-)', alice.decrypt(alice_store, m));
      assert.strictEqual(alice.session_tag.toString(), bob.session_tag.toString());
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('should handle simultaneous repeated messages', function(done) {
    var alice, alice_bundle, alice_ident, alice_prekey, alice_store, bob, bob_bundle, bob_ident, bob_prekey, bob_store, echo_alice1, echo_alice2, echo_bob1, echo_bob2, hello_alice, hello_bob, ref, ref1, stop_bob;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice_prekey = alice_store.prekeys[0];
    alice_bundle = Proteus.keys.PreKeyBundle["new"](alice_ident.public_key, alice_prekey);
    alice = null;
    bob = null;
    hello_bob = null;
    echo_bob1 = null;
    echo_bob2 = null;
    stop_bob = null;
    hello_alice = null;
    echo_alice1 = null;
    echo_alice2 = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob!');
    }).then(function(m) {
      hello_bob = m;
      return Proteus.session.Session.init_from_prekey(bob_ident, alice_bundle);
    }).then(function(s) {
      bob = s;
      return bob.encrypt('Hello Alice!');
    }).then(function(m) {
      hello_alice = m;
      assert(alice.session_tag.toString() !== bob.session_tag.toString());
      return assert_decrypt('Hello Bob!', bob.decrypt(bob_store, hello_bob));
    }).then(function() {
      return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice));
    }).then(function() {
      return alice.encrypt('Echo Bob1!');
    }).then(function(m) {
      echo_bob1 = m;
      return bob.encrypt('Echo Alice1!');
    }).then(function(m) {
      echo_alice1 = m;
      assert_decrypt('Echo Bob1!', bob.decrypt(bob_store, echo_bob1));
      assert(Object.keys(bob.session_states).length === 2);
      assert_decrypt('Echo Alice1!', alice.decrypt(alice_store, echo_alice1));
      assert(Object.keys(alice.session_states).length === 2);
      assert(alice.session_tag.toString() !== bob.session_tag.toString());
      return alice.encrypt('Echo Bob2!');
    }).then(function(m) {
      echo_bob2 = m;
      return bob.encrypt('Echo Alice2!');
    }).then(function(m) {
      echo_alice2 = m;
      return assert_decrypt('Echo Bob2!', bob.decrypt(bob_store, echo_bob2));
    }).then(function() {
      assert(Object.keys(bob.session_states).length === 2);
      return assert_decrypt('Echo Alice2!', alice.decrypt(alice_store, echo_alice2));
    }).then(function() {
      assert(Object.keys(alice.session_states).length === 2);
      assert(alice.session_tag.toString() !== bob.session_tag.toString());
      return alice.encrypt('Stop it!');
    }).then(function(m) {
      stop_bob = m;
      assert_decrypt('Stop it!', bob.decrypt(bob_store, stop_bob));
      return bob.encrypt('OK');
    }).then(function(m) {
      var answer_alice;
      answer_alice = m;
      assert_decrypt('OK', alice.decrypt(alice_store, answer_alice));
      assert(alice.session_tag.toString() === bob.session_tag.toString());
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('should handle mass communication', function(done) {
    var alice, alice_ident, alice_store, bob, bob_bundle, bob_ident, bob_prekey, bob_store, hello_bob, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    hello_bob = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob!');
    }).then(function(m) {
      hello_bob = m;
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    }).then(function(s) {
      var j, results;
      bob = s;

      // XXX: need to serialize/deserialize to/from CBOR here
      return Promise.all((function() {
        results = [];
        for (j = 0; j < 999; j++){ results.push(j); }
        return results;
      }).apply(this).map(function() {
        return bob.encrypt('Hello Alice!');
      }));
    }).then(function(messages) {
      return Promise.all(messages.map(function(m) {
        return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, Proteus.message.Envelope.deserialise(m.serialise())));
      }));
    }).then(function() {
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('should fail retry init from message', function(done) {
    var alice, alice_ident, bob, bob_bundle, bob_ident, bob_prekey, bob_store, hello_bob, ref;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    hello_bob = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob!');
    }).then(function(m) {
      hello_bob = m;
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    }).then(function(s) {
      bob = s;
      return Proteus.session.Session.init_from_message(bob_ident, bob_store, hello_bob);
    }).then(function() {
      return assert.fail('should have thrown Proteus.errors.ProteusError');
    })["catch"](function(e) {
      return assert.instanceOf(e, Proteus.errors.ProteusError);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('pathological case', function(done) {
    var alice_ident, alices, bob, bob_ident, bob_store, num_alices, ref;
    this.timeout(0);
    num_alices = 32;
    alices = null;
    bob = null;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, num_alices));
    return Promise.all(bob_store.prekeys.map(function(pk) {
      var bundle;
      bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, pk);
      return Proteus.session.Session.init_from_prekey(alice_ident, bundle);
    })).then(function(s) {
      alices = s;
      assert(alices.length === num_alices);
      return alices[0].encrypt('Hello Bob!');
    }).then(function(m) {
      return assert_init_from_message(bob_ident, bob_store, m, 'Hello Bob!');
    }).then(function(s) {
      bob = s;
      return Promise.all(alices.map(function(a) {
        return new Promise(function(resolve) {
          var j, results;
          return Promise.all((function() {
            results = [];
            for (j = 0; j <= 900; j++){ results.push(j); }
            return results;
          }).apply(this).map(function() {
            return a.encrypt('hello');
          })).then(function() {
            return a.encrypt('Hello Bob!');
          }).then(function(m) {
            return resolve(assert_decrypt('Hello Bob!', bob.decrypt(bob_store, m)));
          });
        });
      }));
    }).then(function() {
      assert(Object.keys(bob.session_states).length === num_alices);
      return Promise.all(alices.map(function(a) {
        return a.encrypt('Hello Bob!').then(function(m) {
          return assert_decrypt('Hello Bob!', bob.decrypt(bob_store, m));
        });
      }));
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('skipped message keys', function(done) {
    var alice, alice_ident, alice_store, bob, bob_bundle, bob_ident, bob_prekey, bob_store, hello_again0, hello_again1, hello_alice0, hello_alice2, hello_bob, hello_bob0, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));
    }), alice_store = ref1[0], bob_store = ref1[1];
    bob_prekey = bob_store.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    hello_bob = null;
    hello_alice0 = null;
    hello_alice2 = null;
    hello_bob0 = null;
    hello_again0 = null;
    hello_again1 = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob!');
    }).then(function(m) {
      hello_bob = m;
      (function() {
        var s;
        s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 1);
        assert(s.recv_chains[0].chain_key.idx === 0);
        assert(s.send_chain.chain_key.idx === 1);
        return assert(s.recv_chains[0].message_keys.length === 0);
      })();
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    }).then(function(s) {
      bob = s;
      (function() {
        // Normal exchange. Bob has created a new receive chain without skipped message keys.
        s = bob.session_states[bob.session_tag].state;
        assert(s.recv_chains.length === 1);
        assert(s.recv_chains[0].chain_key.idx === 1);
        assert(s.send_chain.chain_key.idx === 0);
        return assert(s.recv_chains[0].message_keys.length === 0);
      })();
      return bob.encrypt('Hello0');
    }).then(function(m) {
      hello_alice0 = m;
      bob.encrypt('Hello1'); // unused result
      return bob.encrypt('Hello2');
    }).then(function(m) {
      hello_alice2 = m;
      return alice.decrypt(alice_store, hello_alice2);
    }).then(function() {
      (function() {
        // Alice has two skipped message keys in her new receive chain.
        var s;
        s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 2);
        assert(s.recv_chains[0].chain_key.idx === 3);
        assert(s.send_chain.chain_key.idx === 0);
        assert(s.recv_chains[0].message_keys.length === 2);
        assert(s.recv_chains[0].message_keys[0].counter === 0);
        return assert(s.recv_chains[0].message_keys[1].counter === 1);
      })();
      return alice.encrypt('Hello0');
    }).then(function(m) {
      hello_bob0 = m;
      return assert_decrypt('Hello0', bob.decrypt(bob_store, hello_bob0));
    }).then(function() {
      (function() {
        // For Bob everything is normal still. A new message from Alice means a
        // new receive chain has been created and again no skipped message keys.
        var s;
        s = bob.session_states[bob.session_tag].state;
        assert(s.recv_chains.length === 2);
        assert(s.recv_chains[0].chain_key.idx === 1);
        assert(s.send_chain.chain_key.idx === 0);
        return assert(s.recv_chains[0].message_keys.length === 0);
      })();
      return assert_decrypt('Hello0', alice.decrypt(alice_store, hello_alice0));
    }).then(function() {
      (function() {

        // Alice received the first of the two missing messages. Therefore
        // only one message key is still skipped (counter value = 1).
        var s;
        s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 2);
        assert(s.recv_chains[0].message_keys.length === 1);
        return assert(s.recv_chains[0].message_keys[0].counter === 1);
      })();
      return bob.encrypt('Again0');
    }).then(function(m) {
      hello_again0 = m;
      return bob.encrypt('Again1');
    }).then(function(m) {
      hello_again1 = m;
      return assert_decrypt('Again1', alice.decrypt(alice_store, hello_again1));
    }).then(function() {
      (function() {

        // Alice received the first of the two missing messages. Therefore
        // only one message key is still skipped (counter value = 1).
        var s;
        s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 3);
        assert(s.recv_chains[0].message_keys.length === 1);
        assert(s.recv_chains[1].message_keys.length === 1);
        assert(s.recv_chains[0].message_keys[0].counter === 0);
        return assert(s.recv_chains[1].message_keys[0].counter === 1);
      })();
      return assert_decrypt('Again0', alice.decrypt(alice_store, hello_again0));
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  it('replaced prekeys', function(done) {
    var alice, alice_ident, bob, bob_bundle, bob_ident, bob_prekey, bob_store1, bob_store2, hello_bob1, hello_bob2, hello_bob3, ref, ref1;
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    ref1 = [0, 1, 2].map(function() {
      return new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 1));
    }), bob_store1 = ref1[0], bob_store2 = ref1[1];
    bob_prekey = bob_store1.prekeys[0];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    hello_bob1 = null;
    hello_bob2 = null;
    hello_bob3 = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob1!');
    }).then(function(m) {
      hello_bob1 = m;
      return assert_init_from_message(bob_ident, bob_store1, hello_bob1, 'Hello Bob1!');
    }).then(function(s) {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);
      return alice.encrypt('Hello Bob2!');
    }).then(function(m) {
      hello_bob2 = m;
      assert_decrypt('Hello Bob2!', bob.decrypt(bob_store1, hello_bob2));
      assert(Object.keys(bob.session_states).length === 1);
      return alice.encrypt('Hello Bob3!');
    }).then(function(m) {
      hello_bob3 = m;
      assert_decrypt('Hello Bob3!', bob.decrypt(bob_store2, hello_bob3));
      return assert(Object.keys(bob.session_states).length === 1);
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
  return it('max counter gap', function(done) {
    var alice, alice_ident, bob, bob_bundle, bob_ident, bob_prekey, bob_store, keys, ref;
    this.timeout(0);
    ref = [0, 1].map(function() {
      return Proteus.keys.IdentityKeyPair["new"]();
    }), alice_ident = ref[0], bob_ident = ref[1];
    keys = [];
    keys[Proteus.keys.PreKey.MAX_PREKEY_ID] = Proteus.keys.PreKey.last_resort();
    bob_store = new TestStore(keys);
    bob_prekey = bob_store.prekeys[Proteus.keys.PreKey.MAX_PREKEY_ID];
    bob_bundle = Proteus.keys.PreKeyBundle["new"](bob_ident.public_key, bob_prekey);
    alice = null;
    bob = null;
    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle).then(function(s) {
      alice = s;
      return alice.encrypt('Hello Bob1!');
    }).then(function(hello_bob1) {
      return assert_init_from_message(bob_ident, bob_store, hello_bob1, 'Hello Bob1!');
    }).then(function(s) {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);
      return Promise.all(Array.apply(null, Array(1001)).map(function(_, i) {
        return new Promise(function(resolve, reject) {
          return alice.encrypt('Hello Bob2!').then(function(hello_bob2) {
            assert_decrypt('Hello Bob2!', bob.decrypt(bob_store, hello_bob2));
            assert.strictEqual(Object.keys(bob.session_states).length, 1);
            return resolve();
          });
        });
      }));
    }).then((function() {
      return done();
    }), function(err) {
      return done(err);
    });
  });
});
