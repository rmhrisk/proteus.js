
// @see https://gist.github.com/xdissent/d20bbdd57ca16b3d86b5, thanks
var ProteusError;

module.exports = ProteusError = (function() {
  function ProteusError(message) {
    this.name = this.constructor.name;
    this.message = message;
    this.stack = (new Error).stack;
  }

  ProteusError.prototype = new Error;

  ProteusError.prototype.constructor = ProteusError;

  return ProteusError;

})();
