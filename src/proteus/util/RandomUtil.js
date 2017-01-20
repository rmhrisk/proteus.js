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

module.exports = (function() {
  var crypto;
  crypto = (typeof window !== 'undefined') && (window.crypto || window.msCrypto);
  if (crypto) {

    // browser
    return (function() {
      return {
        random_bytes: function(len) {
          var buffer, buffer_view;
          buffer = new ArrayBuffer(len);
          buffer_view = new Uint8Array(buffer);
          return crypto.getRandomValues(buffer_view);
        }
      };
    })();
  } else {

    // node
    crypto = require('crypto');
    return (function() {
      return {
        random_bytes: function(len) {
          return new Uint8Array(crypto.randomBytes(len));
        }
      };
    })();
  }
})();
