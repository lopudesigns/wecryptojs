(function(root, factory) {
  if (typeof exports === 'object' && typeof exports.nodeName !== 'string') {
    /* global require */
    factory(exports);
  } else {
    root.node = root.node || {};
    factory((root.node.sjcl = {}));
  }
})(this, function(exports) {

  // INSERT

});
