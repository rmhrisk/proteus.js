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
