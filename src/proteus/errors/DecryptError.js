var DecryptError, ProteusError,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

ProteusError = require('./ProteusError');

DecryptError = (function(superClass) {
  extend(DecryptError, superClass);

  function DecryptError(message) {
    this.message = message != null ? message : 'Unknown decryption error';
  }

  return DecryptError;

})(ProteusError);

DecryptError.RemoteIdentityChanged = (function(superClass) {
  extend(RemoteIdentityChanged, superClass);

  function RemoteIdentityChanged(message) {
    this.message = message != null ? message : 'Remote identity changed';
  }

  return RemoteIdentityChanged;

})(DecryptError);

DecryptError.InvalidSignature = (function(superClass) {
  extend(InvalidSignature, superClass);

  function InvalidSignature(message) {
    this.message = message != null ? message : 'Invalid signature';
  }

  return InvalidSignature;

})(DecryptError);

DecryptError.InvalidMessage = (function(superClass) {
  extend(InvalidMessage, superClass);

  function InvalidMessage(message) {
    this.message = message != null ? message : 'Invalid message';
  }

  return InvalidMessage;

})(DecryptError);

DecryptError.DuplicateMessage = (function(superClass) {
  extend(DuplicateMessage, superClass);

  function DuplicateMessage(message) {
    this.message = message != null ? message : 'Duplicate message';
  }

  return DuplicateMessage;

})(DecryptError);

DecryptError.TooDistantFuture = (function(superClass) {
  extend(TooDistantFuture, superClass);

  function TooDistantFuture(message) {
    this.message = message != null ? message : 'Message is from too distant in the future';
  }

  return TooDistantFuture;

})(DecryptError);

DecryptError.OutdatedMessage = (function(superClass) {
  extend(OutdatedMessage, superClass);

  function OutdatedMessage(message) {
    this.message = message != null ? message : 'Outdated message';
  }

  return OutdatedMessage;

})(DecryptError);

DecryptError.PrekeyNotFound = (function(superClass) {
  extend(PrekeyNotFound, superClass);

  function PrekeyNotFound(message) {
    this.message = message != null ? message : 'Pre-key not found';
  }

  return PrekeyNotFound;

})(DecryptError);

module.exports = DecryptError;
