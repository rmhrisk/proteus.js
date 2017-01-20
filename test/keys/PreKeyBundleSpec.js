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

describe('PreKeyBundle', function() {
  it('should create a bundle', function() {
    var bundle, id_pair, prekey;
    id_pair = Proteus.keys.IdentityKeyPair.new();
    prekey = Proteus.keys.PreKey.new(1);
    bundle = Proteus.keys.PreKeyBundle.new(id_pair.public_key, prekey);
    return assert(bundle.verify() === Proteus.keys.PreKeyAuth.UNKNOWN);
  });
  it('should create a valid signed bundle', function() {
    var bundle, id_pair, prekey;
    id_pair = Proteus.keys.IdentityKeyPair.new();
    prekey = Proteus.keys.PreKey.new(1);
    bundle = Proteus.keys.PreKeyBundle.signed(id_pair, prekey);
    return assert(bundle.verify() === Proteus.keys.PreKeyAuth.VALID);
  });
  it('should serialise and deserialise a unsigned bundle', function() {
    var bundle, id_pair, pkb_bytes, pkb_copy, prekey;
    id_pair = Proteus.keys.IdentityKeyPair.new();
    prekey = Proteus.keys.PreKey.new(1);
    bundle = Proteus.keys.PreKeyBundle.new(id_pair.public_key, prekey);
    assert(bundle.verify() === Proteus.keys.PreKeyAuth.UNKNOWN);
    pkb_bytes = bundle.serialise();
    pkb_copy = Proteus.keys.PreKeyBundle.deserialise(pkb_bytes);
    assert(pkb_copy.verify() === Proteus.keys.PreKeyAuth.UNKNOWN);
    assert(pkb_copy.version === bundle.version);
    assert(pkb_copy.prekey_id === bundle.prekey_id);
    assert(pkb_copy.public_key.fingerprint() === bundle.public_key.fingerprint());
    assert(pkb_copy.identity_key.fingerprint() === bundle.identity_key.fingerprint());
    assert(pkb_copy.signature === bundle.signature);
    return assert(sodium.to_hex(new Uint8Array(pkb_bytes)) === sodium.to_hex(new Uint8Array(pkb_copy.serialise())));
  });
  it('should serialise and deserialise a signed bundle', function() {
    var bundle, id_pair, pkb_bytes, pkb_copy, prekey;
    id_pair = Proteus.keys.IdentityKeyPair.new();
    prekey = Proteus.keys.PreKey.new(1);
    bundle = Proteus.keys.PreKeyBundle.signed(id_pair, prekey);
    assert(bundle.verify() === Proteus.keys.PreKeyAuth.VALID);
    pkb_bytes = bundle.serialise();
    pkb_copy = Proteus.keys.PreKeyBundle.deserialise(pkb_bytes);
    assert(pkb_copy.verify() === Proteus.keys.PreKeyAuth.VALID);
    assert(pkb_copy.version === bundle.version);
    assert(pkb_copy.prekey_id === bundle.prekey_id);
    assert(pkb_copy.public_key.fingerprint() === bundle.public_key.fingerprint());
    assert(pkb_copy.identity_key.fingerprint() === bundle.identity_key.fingerprint());
    assert(sodium.to_hex(pkb_copy.signature) === sodium.to_hex(bundle.signature));
    return assert(sodium.to_hex(new Uint8Array(pkb_bytes)) === sodium.to_hex(new Uint8Array(pkb_copy.serialise())));
  });
  return it('should generate a serialised JSON format', function() {
    var deserialised_pre_key_bundle, identity_key_pair, pre_key, pre_key_bundle, pre_key_id,
        public_identity_key, serialised_array_buffer, serialised_array_buffer_view,
        serialised_pre_key_bundle_json;
    identity_key_pair = Proteus.keys.IdentityKeyPair.new();
    pre_key_id = 72;
    pre_key = Proteus.keys.PreKey.new(pre_key_id);
    public_identity_key = identity_key_pair.public_key;
    pre_key_bundle = Proteus.keys.PreKeyBundle.new(public_identity_key, pre_key);
    serialised_pre_key_bundle_json = pre_key_bundle.serialised_json();
    assert.strictEqual(serialised_pre_key_bundle_json.id, pre_key_id);
    serialised_array_buffer_view = sodium.from_base64(serialised_pre_key_bundle_json.key);
    serialised_array_buffer = serialised_array_buffer_view.buffer;
    deserialised_pre_key_bundle = Proteus.keys.PreKeyBundle.deserialise(serialised_array_buffer);
    return assert.deepEqual(deserialised_pre_key_bundle.public_key, pre_key_bundle.public_key);
  });
});
