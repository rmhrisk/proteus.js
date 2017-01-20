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

describe('HMAC-based Key Derivation Function', function() {
  it('converts a hexadecimal value into a byte array', function() {
    var actual, expected, hex;
    hex = 'a0193d1e7f47b0fe93806606db934f2b248b90a5586ee8666ef67f7d1589bb282893c48280b6004bfbe751912827af624867b7c830c9974fd5324113d2bdc43ee6df4d164cd2bcef6395bef8b843414ac42d225f8bdd7f8121d8465325c63b00';
    actual = Proteus.util.ArrayUtil.hex_to_byte_array(hex);
    expected = [160, 25, 61, 30, 127, 71, 176, 254, 147, 128, 102, 6, 219, 147, 79, 43, 36, 139, 144, 165, 88, 110, 232, 102, 110, 246, 127, 125, 21, 137, 187, 40, 40, 147, 196, 130, 128, 182, 0, 75, 251, 231, 81, 145, 40, 39, 175, 98, 72, 103, 183, 200, 48, 201, 151, 79, 213, 50, 65, 19, 210, 189, 196, 62, 230, 223, 77, 22, 76, 210, 188, 239, 99, 149, 190, 248, 184, 67, 65, 74, 196, 45, 34, 95, 139, 221, 127, 129, 33, 216, 70, 83, 37, 198, 59, 0];
    return assert.deepEqual(actual, expected);
  });
  it('converts a byte array into a hexadecimal value', function() {
    var actual, byte_array, expected;
    byte_array = [160, 25, 61, 30, 127, 71, 176, 254, 147, 128, 102, 6, 219, 147, 79, 43, 36, 139, 144, 165, 88, 110, 232, 102, 110, 246, 127, 125, 21, 137, 187, 40, 40, 147, 196, 130, 128, 182, 0, 75, 251, 231, 81, 145, 40, 39, 175, 98, 72, 103, 183, 200, 48, 201, 151, 79, 213, 50, 65, 19, 210, 189, 196, 62, 230, 223, 77, 22, 76, 210, 188, 239, 99, 149, 190, 248, 184, 67, 65, 74, 196, 45, 34, 95, 139, 221, 127, 129, 33, 216, 70, 83, 37, 198, 59, 0];
    actual = Proteus.util.ArrayUtil.byte_array_to_hex(byte_array);
    expected = 'a0193d1e7f47b0fe93806606db934f2b248b90a5586ee8666ef67f7d1589bb282893c48280b6004bfbe751912827af624867b7c830c9974fd5324113d2bdc43ee6df4d164cd2bcef6395bef8b843414ac42d225f8bdd7f8121d8465325c63b00';
    return assert.deepEqual(actual, expected);
  });
  it('converts a string value into a byte array', function() {
    var actual, expected, string;
    string = 'handshake';
    actual = Proteus.util.ArrayUtil.string_to_byte_array(string);
    expected = [104, 97, 110, 100, 115, 104, 97, 107, 101];
    return assert.deepEqual(actual, expected);
  });
  it('converts byte array into a bit array', function() {
    var actual, expected, input;
    input = [104, 97, 115, 104, 95, 114, 97, 116, 99, 104, 101, 116];
    actual = Proteus.util.ArrayUtil.byte_array_to_bit_array(input);
    expected = [1751217000, 1601331572, 1667786100];
    return assert.deepEqual(actual, expected);
  });
  return it('concatenates buffers together', function() {
    assert.deepEqual(Proteus.util.ArrayUtil.concatenate_array_buffers([new Uint8Array([1, 2, 3])]), new Uint8Array([1, 2, 3]));
    assert.deepEqual(Proteus.util.ArrayUtil.concatenate_array_buffers([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])]), new Uint8Array([1, 2, 3, 4, 5, 6]));
    assert.deepEqual(Proteus.util.ArrayUtil.concatenate_array_buffers([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]), new Uint8Array([7, 8, 9])]), new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
    return assert.deepEqual(Proteus.util.ArrayUtil.concatenate_array_buffers([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]), new Uint8Array([7, 8, 9]), new Uint8Array([10, 11, 12])]), new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
  });
});
