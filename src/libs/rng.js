(function() {
  var g = ('undefined' === typeof window ? global : window) || {}
  var _crypto = (
    g.crypto || g.msCrypto || {}
  )
  module.exports = function(size) {
    // Modern Browsers
    if(_crypto.getRandomValues) {
      var bytes = new Buffer(size); //in browserify, this is an extended Uint8Array
      /* This will not work in older browsers.
       * See https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues
       */
    
      _crypto.getRandomValues(bytes);
      return bytes;
    } else if (_crypto.randomBytes) {
      return _crypto.randomBytes(size)
    } else {
      var bytes = new Buffer(size);
      bytes.fill(function(){return Math.random()*254|0+1;});
      return bytes;
    }
  }
}())
