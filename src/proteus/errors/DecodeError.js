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

const extend = function (child, parent) {
  for (let key in parent) {
    if ({}.hasOwnProperty.call(parent, key)) child[key] = parent[key];
  }
  function ctor () {
    this.constructor = child;
  }
  ctor.prototype = parent.prototype;
  child.prototype = new ctor();
  child.__super__ = parent.prototype;
  return child;
};

const ProteusError = require('./ProteusError');

const DecodeError = (function (superClass) {
  extend(DecodeError, superClass);

  function DecodeError (message) {
    this.message = message != null ? message : 'Unknown decoding error';
  }

  return DecodeError;

})(ProteusError);

DecodeError.InvalidType = (function (superClass) {
  extend(InvalidType, superClass);

  function InvalidType (message) {
    this.message = message != null ? message : 'Invalid type';
  }

  return InvalidType;

})(DecodeError);

DecodeError.InvalidArrayLen = (function (superClass) {
  extend(InvalidArrayLen, superClass);

  function InvalidArrayLen (message) {
    this.message = message != null ? message : 'Invalid array length';
  }

  return InvalidArrayLen;

})(DecodeError);

DecodeError.LocalIdentityChanged = (function (superClass) {
  extend(LocalIdentityChanged, superClass);

  function LocalIdentityChanged (message) {
    this.message = message != null ? message : 'Local identity changed';
  }

  return LocalIdentityChanged;

})(DecodeError);

module.exports = DecodeError;
