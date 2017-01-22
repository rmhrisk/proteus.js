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

var CipherKey, ClassUtil, DerivedSecrets, DontCallConstructor, KeyDerivationUtil, MacKey;

DontCallConstructor = require('../errors/DontCallConstructor');

ClassUtil = require('../util/ClassUtil');

KeyDerivationUtil = require('../util/KeyDerivationUtil');

CipherKey = require('./CipherKey');

MacKey = require('./MacKey');

module.exports = DerivedSecrets = (function() {
  function DerivedSecrets() {
    throw new DontCallConstructor(this);
  }

  DerivedSecrets.kdf = function(input, salt, info) {
    var byte_length, cipher_key, ds, mac_key, okm;
    byte_length = 64;
    okm = KeyDerivationUtil.hkdf(salt, input, info, byte_length);
    cipher_key = new Uint8Array(okm.buffer.slice(0, 32));
    mac_key = new Uint8Array(okm.buffer.slice(32, 64));
    ds = ClassUtil.new_instance(DerivedSecrets);
    ds.cipher_key = CipherKey.new(cipher_key);
    ds.mac_key = MacKey.new(mac_key);
    return ds;
  };


  /*
   * @param input [Array<Integer>] Initial key material (usually the Master Key) in byte array format
   * @param info [String] Key Derivation Data
   */

  DerivedSecrets.kdf_without_salt = function(input, info) {
    return this.kdf(input, new Uint8Array(0), info);
  };

  return DerivedSecrets;

})();
