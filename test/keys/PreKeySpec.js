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

describe('PreKey', function() {
  describe('Generation', function() {
    it('should generate new PreKeys', function() {
      var pk;
      pk = Proteus.keys.PreKey["new"](0);
      pk = Proteus.keys.PreKey.last_resort();
      return assert(pk.key_id === Proteus.keys.PreKey.MAX_PREKEY_ID);
    });
    it('should reject invalid PreKey IDs', function() {
      assert.throws(function() {
        return Proteus.keys.PreKey["new"](void 0);
      });
      assert.throws(function() {
        return Proteus.keys.PreKey["new"]("foo");
      });
      assert.throws(function() {
        return Proteus.keys.PreKey["new"](-1);
      });
      assert.throws(function() {
        return Proteus.keys.PreKey["new"](65537);
      });
      return assert.throws(function() {
        return Proteus.keys.PreKey["new"](4242.42);
      });
    });
    it('generates ranges of PreKeys', function() {
      var prekeys;
      prekeys = Proteus.keys.PreKey.generate_prekeys(0, 0);
      assert.strictEqual(prekeys.length, 0);
      prekeys = Proteus.keys.PreKey.generate_prekeys(0, 1);
      assert.strictEqual(prekeys.length, 1);
      assert(prekeys[0].key_id === 0);
      prekeys = Proteus.keys.PreKey.generate_prekeys(0, 10);
      assert(prekeys.length === 10);
      assert(prekeys[0].key_id === 0);
      assert(prekeys[9].key_id === 9);
      prekeys = Proteus.keys.PreKey.generate_prekeys(3000, 10);
      assert(prekeys.length === 10);
      assert(prekeys[0].key_id === 3000);
      return assert(prekeys[9].key_id === 3009);
    });
    return it('does not include the last resort pre key', function() {
      var prekeys;
      prekeys = Proteus.keys.PreKey.generate_prekeys(65530, 10);
      assert(prekeys.length === 10);
      assert(prekeys[0].key_id === 65530);
      assert(prekeys[1].key_id === 65531);
      assert(prekeys[2].key_id === 65532);
      assert(prekeys[3].key_id === 65533);
      assert(prekeys[4].key_id === 65534);
      assert(prekeys[5].key_id === 0);
      assert(prekeys[6].key_id === 1);
      assert(prekeys[7].key_id === 2);
      assert(prekeys[8].key_id === 3);
      assert(prekeys[9].key_id === 4);
      prekeys = Proteus.keys.PreKey.generate_prekeys(Proteus.keys.PreKey.MAX_PREKEY_ID, 1);
      assert.strictEqual(prekeys.length, 1);
      return assert(prekeys[0].key_id === 0);
    });
  });
  return describe('Serialisation', function() {
    return it('should serialise and deserialise correctly', function() {
      var pk, pk_bytes, pk_copy;
      pk = Proteus.keys.PreKey["new"](0);
      pk_bytes = pk.serialise();
      pk_copy = Proteus.keys.PreKey.deserialise(pk_bytes);
      assert(pk_copy.version === pk.version);
      assert(pk_copy.key_id === pk.key_id);
      assert(pk_copy.key_pair.public_key.fingerprint() === pk.key_pair.public_key.fingerprint());
      return assert(sodium.to_hex(new Uint8Array(pk_bytes)) === sodium.to_hex(new Uint8Array(pk_copy.serialise())));
    });
  });
});
