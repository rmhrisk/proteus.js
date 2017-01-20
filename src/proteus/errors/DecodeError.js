var DecodeError, ProteusError,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

ProteusError = require('./ProteusError');

DecodeError = (function(superClass) {
  extend(DecodeError, superClass);

  function DecodeError(message) {
    this.message = message != null ? message : 'Unknown decoding error';
  }

  return DecodeError;

})(ProteusError);

DecodeError.InvalidType = (function(superClass) {
  extend(InvalidType, superClass);

  function InvalidType(message) {
    this.message = message != null ? message : 'Invalid type';
  }

  return InvalidType;

})(DecodeError);

DecodeError.InvalidArrayLen = (function(superClass) {
  extend(InvalidArrayLen, superClass);

  function InvalidArrayLen(message) {
    this.message = message != null ? message : 'Invalid array length';
  }

  return InvalidArrayLen;

})(DecodeError);

DecodeError.LocalIdentityChanged = (function(superClass) {
  extend(LocalIdentityChanged, superClass);

  function LocalIdentityChanged(message) {
    this.message = message != null ? message : 'Local identity changed';
  }

  return LocalIdentityChanged;

})(DecodeError);

module.exports = DecodeError;
