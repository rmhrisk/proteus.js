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

var DontCallConstructor, ProteusError,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

ProteusError = require('./ProteusError');

module.exports = DontCallConstructor = (function(superClass) {
  extend(DontCallConstructor, superClass);

  function DontCallConstructor(_instance) {
    this._instance = _instance;
    DontCallConstructor.__super__.constructor.call(this, "Instead of 'new " + this._instance.constructor.name + "', use '" + this._instance.constructor.name + ".new'.");
  }

  return DontCallConstructor;

})(ProteusError);
