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

class TestStore extends Proteus.session.PreKeyStore {
  constructor (prekeys) {
    super();
    this.prekeys = prekeys;
  }

  get_prekey (prekey_id) {
    return new Promise((resolve, reject) => {
      resolve(this.prekeys[prekey_id]);
    });
  }

  remove (prekey_id) {
    return new Promise((resolve, reject) => {
      delete this.prekeys[prekey_id];
      resolve();
    });
  }
}

const assert_init_from_message = (ident, store, msg, expected) => {
  return new Promise((resolve, reject) => {
    Proteus.session.Session.init_from_message(ident, store, msg)

    .then((x) => {
      const [s, msg] = x;
      assert.strictEqual(sodium.to_string(msg), expected);
      resolve(s);
    })

    .catch((e) => {
      reject(e);
    });
  });
};

const assert_decrypt = (expected, p) => {
  return new Promise((resolve, reject) => {
    p.then((actual) => {
      assert.strictEqual(expected, sodium.to_string(actual));
      resolve();
    })

    .catch((e) => {
      reject(e);
    });
  });
};

const assert_prev_count = (session, expected) => {
  assert.strictEqual(
    expected,
    session.session_states[session.session_tag].state.prev_counter
  );
};

const assert_serialise_deserialise = (local_identity, session) => {
  const bytes = session.serialise();

  const deser = Proteus.session.Session.deserialise(local_identity, bytes);
  const deser_bytes = deser.serialise();

  assert.deepEqual(
    sodium.to_hex(new Uint8Array(bytes)),
    sodium.to_hex(new Uint8Array(deser_bytes))
  );
};

describe('Session', () => {
  it('can be serialised and deserialised to/from CBOR', () => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((alice) => {
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);
      assert_serialise_deserialise(alice_ident, alice);
    });
  });

  it('encrypts and decrypts messages', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    let hello_bob = null;
    let hello_bob_delayed = null;
    let hello_alice = null;
    let ping_bob_1 = null;
    let ping_bob_2 = null;
    let pong_alice = null;

    Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;

      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);

      return Promise.all(['Hello Bob!', 'Hello delay!'].map((x) => alice.encrypt(x)));
    })

    .then((msgs) => {
      [ hello_bob, hello_bob_delayed ] = msgs;

      assert(Object.keys(alice.session_states).length === 1);
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);

      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    })

    .then((s) => {
      bob = s;

      assert(Object.keys(bob.session_states).length === 1);
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 1);

      return bob.encrypt('Hello Alice!');
    })

    .then((m) => {
      hello_alice = m;
      return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice));
    })

    .then(() => {
      assert(alice.pending_prekey === null);
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 2);
      assert(alice.remote_identity.fingerprint() === bob.local_identity.public_key.fingerprint());

      return Promise.all(['Ping1!', 'Ping2!'].map((x) => alice.encrypt(x)));
    })

    .then((msgs) => {
      [ ping_bob_1, ping_bob_2 ] = msgs;

      assert_prev_count(alice, 2);

      assert(ping_bob_1.message instanceof Proteus.message.CipherMessage);
      assert(ping_bob_2.message instanceof Proteus.message.CipherMessage);

      return assert_decrypt('Ping1!', bob.decrypt(bob_store, ping_bob_1));
    })

    .then(() => {
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 2);
      return assert_decrypt('Ping2!', bob.decrypt(bob_store, ping_bob_2));
    })

    .then(() => {
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 2);
      return bob.encrypt('Pong!');
    })

    .then((m) => {
      pong_alice = m;
      assert_prev_count(bob, 1);
      return assert_decrypt('Pong!', alice.decrypt(alice_store, pong_alice));
    })

    .then(() => {
      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 3);
      assert_prev_count(alice, 2);
      return assert_decrypt('Hello delay!', bob.decrypt(bob_store, hello_bob_delayed));
    })

    .then(() => {
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 2);
      assert_prev_count(bob, 1);

      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    })

    .then(() => done(), (err) => done(err));
  });

  it('should limit the number of receive chains', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((hello_bob) => assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!'))

    .then((s) => {
      bob = s;

      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 1);

      return Promise.all(
        Array.from(
          { length: Proteus.session.Session.MAX_RECV_CHAINS * 2 },
          () => {
            return new Promise((resolve, reject) => {
              return bob.encrypt('ping')
              .then((m) => assert_decrypt('ping', alice.decrypt(alice_store, m)))

              .then(() => alice.encrypt('pong'))

              .then((m) => assert_decrypt('pong', bob.decrypt(bob_store, m)))

              .then(() => {
                assert.isAtMost(
                  alice.session_states[alice.session_tag].state.recv_chains.length,
                  Proteus.session.Session.MAX_RECV_CHAINS
                );
                assert.isAtMost(
                  bob.session_states[bob.session_tag].state.recv_chains.length,
                  Proteus.session.Session.MAX_RECV_CHAINS
                );
                resolve();
              });
            });
          }
        )
      );
    })

    .then(() => done(), (err) => done(err));
  });

  it('should handle a counter mismatch', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    let ciphertexts = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((m) => assert_init_from_message(bob_ident, bob_store, m, 'Hello Bob!'))

    .then((s) => {
      bob = s;
      return Promise.all(
        ['Hello1', 'Hello2', 'Hello3', 'Hello4', 'Hello5'].map((x) => bob.encrypt(x))
      );
    })

    .then((t) => {
      ciphertexts = t;
      return assert_decrypt('Hello2', alice.decrypt(alice_store, ciphertexts[1]));
    })

    .then(() => {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 1);
      assert_serialise_deserialise(alice_ident, alice);
      return assert_decrypt('Hello1', alice.decrypt(alice_store, ciphertexts[0]));
    })

    .then(() => {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 0);
      return assert_decrypt('Hello3', alice.decrypt(alice_store, ciphertexts[2]));
    })

    .then(() => {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 0);
      return assert_decrypt('Hello5', alice.decrypt(alice_store, ciphertexts[4]));
    })

    .then(() => {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 1);
      return assert_decrypt('Hello4', alice.decrypt(alice_store, ciphertexts[3]));
    })

    .then(() => {
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length === 0);
      return Promise.all(ciphertexts.map((x) => {
        return new Promise((resolve, reject) => {
          return alice.decrypt(alice_store, x)
          .then(() => assert.fail('should have raised Proteus.errors.DecryptError.DuplicateMessage'))

          .catch((e) => {
            assert.instanceOf(e, Proteus.errors.DecryptError.DuplicateMessage);
            resolve();
          });
        });
      }));
    })

    .then(() => {
      assert_serialise_deserialise(alice_ident, alice);
      assert_serialise_deserialise(bob_ident, bob);
    })

    .then(() => done(), (err) => done(err));
  });

  it('should handle multiple prekey messages', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    let hello_bob1 = null;
    let hello_bob2 = null;
    let hello_bob3 = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return Promise.all(
        ['Hello Bob1!', 'Hello Bob2!', 'Hello Bob3!'].map((x) => alice.encrypt(x))
      );
    })

    .then((m) => {
      [ hello_bob1, hello_bob2, hello_bob3 ] = m;
      return assert_init_from_message(bob_ident, bob_store, hello_bob1, 'Hello Bob1!');
    })

    .then((s) => {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);
      return assert_decrypt('Hello Bob2!', bob.decrypt(bob_store, hello_bob2));
    })

    .then(() => {
      assert(Object.keys(bob.session_states).length === 1);
      return assert_decrypt('Hello Bob3!', bob.decrypt(bob_store, hello_bob3));
    })

    .then(() => {
      assert(Object.keys(bob.session_states).length === 1);
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    })

    .then(() => done(), (err) => done(err));
  });

  it('should handle simultaneous prekey messages', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(() => Proteus.keys.IdentityKeyPair.new());
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    const alice_prekey = alice_store.prekeys[0];
    const alice_bundle = Proteus.keys.PreKeyBundle.new(alice_ident.public_key, alice_prekey);

    let alice = null;
    let bob = null;

    let hello_bob = null;
    let hello_alice = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((m) => {
      hello_bob = m;
      bob = Proteus.session.Session.init_from_prekey(bob_ident, alice_bundle);
      return bob;
    })

    .then((s) => {
      bob = s;
      return bob.encrypt('Hello Alice!');
    })

    .then((m) => {
      hello_alice = m;
      assert.notStrictEqual(alice.session_tag.toString(), bob.session_tag.toString());
      return assert_decrypt('Hello Bob!', bob.decrypt(bob_store, hello_bob));
    })

    .then(() => {
      assert(Object.keys(bob.session_states).length === 2);
      return assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice));
    })

    .then(() => {
      assert(Object.keys(alice.session_states).length === 2);
      return alice.encrypt('That was fast!');
    })

    .then((m) => {
      assert_decrypt('That was fast!', bob.decrypt(bob_store, m));
      return bob.encrypt(':-)');
    })

    .then((m) => {
      assert_decrypt(':-)', alice.decrypt(alice_store, m));

      assert.strictEqual(alice.session_tag.toString(), bob.session_tag.toString());

      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    })

    .then(() => done(), (err) => done(err));
  });

  it('should handle simultaneous repeated messages', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    const alice_prekey = alice_store.prekeys[0];
    const alice_bundle = Proteus.keys.PreKeyBundle.new(alice_ident.public_key, alice_prekey);

    let alice = null;
    let bob = null;

    let hello_bob = null;
    let echo_bob1 = null;
    let echo_bob2 = null;
    let stop_bob = null;
    let hello_alice = null;
    let echo_alice1 = null;
    let echo_alice2 = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((m) => {
      hello_bob = m;
      return Proteus.session.Session.init_from_prekey(bob_ident, alice_bundle);
    })

    .then((s) => {
      bob = s;
      return bob.encrypt('Hello Alice!');
    })

    .then((m) => {
      hello_alice = m;
      assert(alice.session_tag.toString() !== bob.session_tag.toString());
      return assert_decrypt('Hello Bob!', bob.decrypt(bob_store, hello_bob));
    })

    .then(() => assert_decrypt('Hello Alice!', alice.decrypt(alice_store, hello_alice)))

    .then(() => alice.encrypt('Echo Bob1!'))

    .then((m) => {
      echo_bob1 = m;
      return bob.encrypt('Echo Alice1!');
    })

    .then((m) => {
      echo_alice1 = m;

      assert_decrypt('Echo Bob1!', bob.decrypt(bob_store, echo_bob1));
      assert(Object.keys(bob.session_states).length === 2);
      assert_decrypt('Echo Alice1!', alice.decrypt(alice_store, echo_alice1));
      assert(Object.keys(alice.session_states).length === 2);
      assert(alice.session_tag.toString() !== bob.session_tag.toString());

      return alice.encrypt('Echo Bob2!');
    })

    .then((m) => {
      echo_bob2 = m;
      return bob.encrypt('Echo Alice2!');
    })

    .then((m) => {
      echo_alice2 = m;
      return assert_decrypt('Echo Bob2!', bob.decrypt(bob_store, echo_bob2));
    })

    .then(() => {
      assert(Object.keys(bob.session_states).length === 2);
      return assert_decrypt('Echo Alice2!', alice.decrypt(alice_store, echo_alice2));
    })

    .then(() => {
      assert(Object.keys(alice.session_states).length === 2);
      assert(alice.session_tag.toString() !== bob.session_tag.toString());
      return alice.encrypt('Stop it!');
    })

    .then((m) => {
      stop_bob = m;
      assert_decrypt('Stop it!', bob.decrypt(bob_store, stop_bob));
      return bob.encrypt('OK');
    })

    .then((m) => {
      const answer_alice = m;
      assert_decrypt('OK', alice.decrypt(alice_store, answer_alice));

      assert(alice.session_tag.toString() === bob.session_tag.toString());

      assert_serialise_deserialise(alice_ident, alice);
      assert_serialise_deserialise(bob_ident, bob);
    })

    .then(() => done(), (err) => done(err));
  });

  it('should handle mass communication', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;
    let hello_bob = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)

    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((m) => {
      hello_bob = m;
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    })

    .then((s) => {
      bob = s;

      // XXX: need to serialize/deserialize to/from CBOR here
      return Promise.all(Array.from({ length: 999 }, () => bob.encrypt('Hello Alice!')));
    })

    .then((messages) => {
      return Promise.all(
        messages.map((m) => assert_decrypt(
          'Hello Alice!',
          alice.decrypt(alice_store, Proteus.message.Envelope.deserialise(m.serialise()))
        ))
      );
    })

    .then(() => {
      assert_serialise_deserialise(alice_ident, alice);
      return assert_serialise_deserialise(bob_ident, bob);
    })

    .then(() => done(), (err) => done(err));
  });

  it('should fail retry init from message', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10));

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;
    let hello_bob = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((m) => {
      hello_bob = m;
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    })

    .then((s) => {
      bob = s;
      return Proteus.session.Session.init_from_message(bob_ident, bob_store, hello_bob);
    })

    .then(() => assert.fail('should have thrown Proteus.errors.ProteusError'))

    .catch((e) => assert.instanceOf(e, Proteus.errors.ProteusError))

    .then(() => done(), (err) => done(err));
  });

  it('pathological case', function (done) {
    this.timeout(0);

    const num_alices = 32;

    let alices = null;
    let bob = null;

    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const bob_store = new TestStore(Proteus.keys.PreKey.generate_prekeys(0, num_alices));

    Promise.all(bob_store.prekeys.map((pk) => {
      const bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, pk);
      return Proteus.session.Session.init_from_prekey(alice_ident, bundle);
    }))

    .then((s) => {
      alices = s;
      assert(alices.length === num_alices);
      return alices[0].encrypt('Hello Bob!');
    })

    .then((m) => assert_init_from_message(bob_ident, bob_store, m, 'Hello Bob!'))

    .then((s) => {
      bob = s;

      return Promise.all(alices.map((a) => {
        return new Promise((resolve) => {
          Promise.all(Array.from({ length: 900 }, () => a.encrypt('hello')))

          .then(() => a.encrypt('Hello Bob!'))

          .then((m) => resolve(assert_decrypt('Hello Bob!', bob.decrypt(bob_store, m))));
        });
      }));
    })

    .then(() => {
      assert(Object.keys(bob.session_states).length === num_alices);

      return Promise.all(alices.map((a) => {
        return a.encrypt('Hello Bob!')
        .then((m) => assert_decrypt('Hello Bob!', bob.decrypt(bob_store, m)));
      }));
    })

    .then(() => done(), (err) => done(err));
  });

  it('skipped message keys', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;
    let hello_bob = null;
    let hello_alice0 = null;
    let hello_alice2 = null;
    let hello_bob0 = null;
    let hello_again0 = null;
    let hello_again1 = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((m) => {
      hello_bob = m;

      (() => {
        const s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 1);
        assert(s.recv_chains[0].chain_key.idx === 0);
        assert(s.send_chain.chain_key.idx === 1);
        assert(s.recv_chains[0].message_keys.length === 0);
      })();

      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    })

    .then((s) => {
      bob = s;

      (() => {
        // Normal exchange. Bob has created a new receive chain without skipped message keys.

        s = bob.session_states[bob.session_tag].state;
        assert(s.recv_chains.length === 1);
        assert(s.recv_chains[0].chain_key.idx === 1);
        assert(s.send_chain.chain_key.idx === 0);
        return assert(s.recv_chains[0].message_keys.length === 0);
      })();

      return bob.encrypt('Hello0');
    })

    .then((m) => {
      hello_alice0 = m;
      bob.encrypt('Hello1'); // unused result
      return bob.encrypt('Hello2');
    })

    .then((m) => {
      hello_alice2 = m;
      return alice.decrypt(alice_store, hello_alice2);
    })

    .then(() => {
      (() => {
        // Alice has two skipped message keys in her new receive chain.

        const s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 2);
        assert(s.recv_chains[0].chain_key.idx === 3);
        assert(s.send_chain.chain_key.idx === 0);
        assert(s.recv_chains[0].message_keys.length === 2);
        assert(s.recv_chains[0].message_keys[0].counter === 0);
        assert(s.recv_chains[0].message_keys[1].counter === 1);
      })();

      return alice.encrypt('Hello0');
    })

    .then((m) => {
      hello_bob0 = m;
      return assert_decrypt('Hello0', bob.decrypt(bob_store, hello_bob0));
    })

    .then(() => {
      (() => {
        // For Bob everything is normal still. A new message from Alice means a
        // new receive chain has been created and again no skipped message keys.

        const s = bob.session_states[bob.session_tag].state;
        assert(s.recv_chains.length === 2);
        assert(s.recv_chains[0].chain_key.idx === 1);
        assert(s.send_chain.chain_key.idx === 0);

        assert(s.recv_chains[0].message_keys.length === 0);
      })();

      return assert_decrypt('Hello0', alice.decrypt(alice_store, hello_alice0));
    })

    .then(() => {
      (() => {
        // Alice received the first of the two missing messages. Therefore
        // only one message key is still skipped (counter value = 1).

        const s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 2);
        assert(s.recv_chains[0].message_keys.length === 1);
        assert(s.recv_chains[0].message_keys[0].counter === 1);
      })();

      return bob.encrypt('Again0');
    })

    .then((m) => {
      hello_again0 = m;
      return bob.encrypt('Again1');
    })

    .then((m) => {
      hello_again1 = m;
      return assert_decrypt('Again1', alice.decrypt(alice_store, hello_again1));
    })

    .then(() => {
      (() => {

        // Alice received the first of the two missing messages. Therefore
        // only one message key is still skipped (counter value = 1).

        const s = alice.session_states[alice.session_tag].state;
        assert(s.recv_chains.length === 3);
        assert(s.recv_chains[0].message_keys.length === 1);
        assert(s.recv_chains[1].message_keys.length === 1);
        assert(s.recv_chains[0].message_keys[0].counter === 0);
        assert(s.recv_chains[1].message_keys[0].counter === 1);
      })();

      return assert_decrypt('Again0', alice.decrypt(alice_store, hello_again0));
    })

    .then(() => done(), (err) => done(err));
  });

  it('replaced prekeys', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ bob_store1, bob_store2 ] = [0, 1, 2].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 1))
    );

    const bob_prekey = bob_store1.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;
    let hello_bob1 = null;
    let hello_bob2 = null;
    let hello_bob3 = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob1!');
    })

    .then((m) => {
      hello_bob1 = m;
      return assert_init_from_message(bob_ident, bob_store1, hello_bob1, 'Hello Bob1!');
    })

    .then((s) => {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);
      return alice.encrypt('Hello Bob2!');
    })

    .then((m) => {
      hello_bob2 = m;
      assert_decrypt('Hello Bob2!', bob.decrypt(bob_store1, hello_bob2));
      assert(Object.keys(bob.session_states).length === 1);
      return alice.encrypt('Hello Bob3!');
    })

    .then((m) => {
      hello_bob3 = m;
      assert_decrypt('Hello Bob3!', bob.decrypt(bob_store2, hello_bob3));
      assert(Object.keys(bob.session_states).length === 1);
    })

    .then(() => done(), (err) => done(err));
  });

  it('max counter gap', function (done) {
    this.timeout(0);

    const [ alice_ident, bob_ident ] = [0, 1].map(() => Proteus.keys.IdentityKeyPair.new());

    let keys = [];
    keys[Proteus.keys.PreKey.MAX_PREKEY_ID] = Proteus.keys.PreKey.last_resort();
    const bob_store = new TestStore(keys);

    const bob_prekey = bob_store.prekeys[Proteus.keys.PreKey.MAX_PREKEY_ID];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob1!');
    })

    .then((hello_bob1) => assert_init_from_message(bob_ident, bob_store, hello_bob1, 'Hello Bob1!'))

    .then((s) => {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);

      return Promise.all(Array.from({ length: 1001 }, () => {
        return new Promise((resolve, reject) => {
          return alice.encrypt('Hello Bob2!')

          .then((hello_bob2) => {
            assert_decrypt('Hello Bob2!', bob.decrypt(bob_store, hello_bob2));
            assert.strictEqual(Object.keys(bob.session_states).length, 1);
            resolve();
          });
        });
      }));
    })

    .then(() => done(), (err) => done(err));
  });

  it('should limit the number of sessions', (done) => {
    const [ alice_ident, bob_ident ] = [0, 1].map(
      () => Proteus.keys.IdentityKeyPair.new()
    );
    const [ alice_store, bob_store ] = [0, 1].map(
      () => new TestStore(Proteus.keys.PreKey.generate_prekeys(0, 10))
    );

    const bob_prekey = bob_store.prekeys[0];
    const bob_bundle = Proteus.keys.PreKeyBundle.new(bob_ident.public_key, bob_prekey);

    let alice = null;
    let bob = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle)
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((hello_bob) => assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!'))

    .then((s) => {
      bob = s;

      assert(alice.session_states[alice.session_tag].state.recv_chains.length === 1);
      assert(bob.session_states[bob.session_tag].state.recv_chains.length === 1);

      return Promise.all(
        Array.from(
          { length: Proteus.session.Session.MAX_SESSION_STATES + 1 },
          () => {
            return new Promise((resolve, reject) => {
              return bob.encrypt('ping')
              .then((m) => assert_decrypt('ping', alice.decrypt(alice_store, m)))

              .then(() => alice.encrypt('pong'))

              .then((m) => assert_decrypt('pong', bob.decrypt(bob_store, m)))

              .then(() => {
                assert.isAtMost(
                  Object.keys(alice.session_states).length,
                  Proteus.session.Session.MAX_SESSION_STATES
                );
                assert.isAtMost(
                  Object.keys(bob.session_states).length,
                  Proteus.session.Session.MAX_SESSION_STATES
                );
                resolve();
              });
            });
          }
        )
      );
    })

    .then(() => done(), (err) => done(err));
  });

  it('should limit the number of sessions', (done) => {
    const [alice_ident, bob_ident] = [0, 1].map(() => Proteus.keys.IdentityKeyPair.new());
    const bob_store = new TestStore(
      Proteus.keys.PreKey.generate_prekeys(0, (Proteus.session.Session.MAX_SESSION_STATES + 2))
    );

    const bob_bundle = (i, store) => Proteus.keys.PreKeyBundle.new(bob_ident.public_key, store.prekeys[i]);

    let alice = null;
    let bob = null;
    let hello_bob = null;

    return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle(1, bob_store))
    .then((s) => {
      alice = s;
      return alice.encrypt('Hello Bob!');
    })

    .then((m) => {
      hello_bob = m;
      return assert_init_from_message(bob_ident, bob_store, hello_bob, 'Hello Bob!');
    })


    .then((s) => {
      bob = s;
      assert(Object.keys(bob.session_states).length === 1);

      return Promise.all(
        Array.from({ length: (Proteus.session.Session.MAX_SESSION_STATES) }, (obj, i) => {
          return new Promise((resolve, reject) => {
            return Proteus.session.Session.init_from_prekey(alice_ident, bob_bundle(i + 2, bob_store))
            .then((s) => {
              alice = s;
              return alice.encrypt('Hello Bob!');
            })

            .then((m) => {
              hello_bob = m;
              assert_decrypt('Hello Bob!', bob.decrypt(bob_store, m))
            })

            .then(() => resolve(), err => reject(err))
          });
        })
      );
    })

    .then(() => {
      assert.isAtMost(Object.keys(alice.session_states).length, Proteus.session.Session.MAX_SESSION_STATES)
      assert.isAtMost(Object.keys(bob.session_states).length, Proteus.session.Session.MAX_SESSION_STATES)
    })

    .then((() => done()), err => done(err))
  });
});
