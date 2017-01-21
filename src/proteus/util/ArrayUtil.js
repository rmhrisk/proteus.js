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

const TypeUtil = require('../util/TypeUtil');

module.exports = (() => {
  return {
    /*
     * Concatenates array buffers (usually 8-bit unsigned).
     */

    concatenate_array_buffers (buffers) {
      TypeUtil.assert_is_instance(Array, buffers);

      return buffers.reduce((a, b) => {
        const buf = new a.constructor(a.byteLength + b.byteLength);
        buf.set(a, 0);
        buf.set(b, a.byteLength);
        return buf;
      });
    },

    array_buffer_to_string (buffer) {
      return String.fromCharCode.apply(null, buffer);
    },

    /*
     * @see https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String?hl=en
     */
    string_to_array_buffer (str) {
      const array_buffer = new ArrayBuffer(str.length * 2);
      // 2 bytes for each char
      const bufView = new Uint16Array(array_buffer);
      let i = 0;
      strLen = str.length;
      while (i < strLen) {
        bufView[i] = str.charCodeAt(i);
        i++;
      }
      return array_buffer;
    },

    string_to_byte_array (string) {
      const byte_array = [];
      for (let index in string) {
        byte_array.push(string.charCodeAt(index));
      }
      return byte_array;
    },

    string_to_hex (input) {
      let str = '';
      let i = 0;
      const tmp_len = input.length;
      let c = undefined;
      while (i < tmp_len) {
        c = input.charCodeAt(i);
        str += c.toString(16);
        i += 1;
      }
      return str;
    },

    byte_array_to_hex (bytes) {
      let hex = [];
      let i = 0;
      while (i < bytes.length) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
        i++;
      }
      return hex.join('');
    },

    hex_to_byte_array (hex) {
      let bytes = [];
      let c = 0;
      while (c < hex.length) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
        c += 2;
      }
      return bytes;
    },

    byte_array_to_bit_array (byte_array) {
      const bit_array_to_partial_word = (len, x, _end) => {
        if (len === 32) {
          return x;
        }
        return (_end ? x | 0 : x << 32 - len) + len * 0x10000000000;
      };
      let out = [];
      let i = undefined;
      let tmp = 0;
      i = 0;
      while (i < byte_array.length) {
        tmp = tmp << 8 | byte_array[i];
        if ((i & 3) === 3) {
          out.push(tmp);
          tmp = 0;
        }
        i++;
      }
      if (i & 3) {
        out.push(bit_array_to_partial_word(8 * (i & 3), tmp));
      }
      return out;
    }
  };
})();
