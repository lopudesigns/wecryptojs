/* global self */
(function(root, factory) {
  if (typeof exports === 'object' && typeof exports.nodeName !== 'string') {
    // CommonJS
    factory(exports);
  } else {
    // Browser globals
    root.node = root.node || {};
    factory((root.node.crypto = {}));
  }
})(typeof self !== 'undefined' ? self : this, function(exports) {
  exports.PrivateKey = PrivateKey;
  exports.PublicKey = PublicKey;
  exports.generateKeys = generateKeys;
  exports.keysFromPassword = keysFromPassword;
  exports.sha256 = sha256;
  exports.ripemd160 = ripemd160;
  exports.hexify = hexify;

  var sjcl = (function() {
    // SJCL is inserted here automatically by the build process.
    // SJCL_INSERT_POINT

    return sjcl;
  })();

  exports.sjcl = sjcl;

  function PrivateKey(priv, pub) {
    // we deliberately avoid exposing private key material on the instance.
    // this is paranoid and probably doesn't protect against a determined
    // attack, but why make things easy?
    this.getPublicKey = function() {
      if (!pub) {
        pub = sjcl.ecc.ecdsa.generateKeys(
          sjcl.ecc.curves.k256,
          undefined,
          sjcl.bn.fromBits(priv.get())
        ).pub;
      }
      return new PublicKey(pub);
    };

    this.sign = function(hash) {
      return fromBits(sjcl.codec.node.signRecoverably(priv, toBits(hash)));
    };
  }
  PrivateKey.from = function(wif, header) {
    return new PrivateKey(
      sjcl.codec.node.deserializePrivateKey(wif, header)
    );
  };
  function PublicKey(pub) {
    this._p = pub;
  }
  PublicKey.from = function(str) {
    return new PublicKey(sjcl.codec.node.deserializePublicKey(str));
  };
  PublicKey.recover = function(hash, sig) {
    return new PublicKey(
      sjcl.codec.node.recoverPublicKey(toBits(hash), toBits(sig))
    );
  };
  PublicKey.prototype = {
    toString: function() {
      return sjcl.codec.node.serializePublicKey(this._p);
    },
    verify: function(hash, signature) {
      try {
        var rawSig = sjcl.bitArray.bitSlice(toBits(signature), 8);
        this._p.verify(toBits(hash), rawSig);
        return true;
      } catch (_) {
        return false;
      }
    }
  };
  function generateKeys(serialize=true) {
		var k = sjcl.ecc.ecdsa.generateKeys(sjcl.ecc.curves.k256);
		if(serialize){
			return serializePair(k);
		} else {
			return k
		}
  }
  function keysFromPassword(accountName, accountPassword) {
    var keys = sjcl.codec.node.keysFromPassword(
      accountName,
      accountPassword
    );
    return {
      owner: serializePair(keys.owner),
      memo: serializePair(keys.memo),
      posting: serializePair(keys.posting),
      active: serializePair(keys.active)
    };
  }
  function sha256(data) {
		if(typeof data == 'string' && textEncoderPath){
			data = new global[textEncoderPath]().encode(data).buffer
		}
    return fromBits(sjcl.hash.sha256.hash(toBits(data)));
  }
  function ripemd160(data) {
		if(typeof data == 'string' && textEncoderPath){
			data = new global[textEncoderPath]().encode(data).buffer
		}
    return fromBits(sjcl.hash.ripemd160.hash(toBits(data)));
  }
  function hexify(data) {
    var result = '';
    var view = new Uint8Array(data);
    for (var i = 0; i < view.byteLength; i++) {
      if (view[i] < 16) {
        result += '0';
      }
      result += view[i].toString(16);
    }
    return result;
  }
  function serializePair(k) {
    return {
      private: sjcl.codec.node.serializePrivateKey(k.sec),
      public: sjcl.codec.node.serializePublicKey(k.pub)
    };
  }
  function toBits(a) {
		if(typeof a == 'string' && textEncoderPath){
			a = new global[textEncoderPath]().encode(a).buffer
		}
    if (a instanceof ArrayBuffer) {
      return sjcl.codec.arrayBuffer.toBits(a);
    } else {
      throw new Error('You must supply an ArrayBuffer');
    }
  }
  function fromBits(a) {
    return sjcl.codec.arrayBuffer.fromBits(a, 0, 0);
  }
});

var window
var global
var util

let textEncoderPath = (window && window.TextEncoder) ? 'window' : (util && util.TextEncoder) ? 'util' : (global && global.TextEncoder) ? 'global' : (global && global.util && global.util.TextEncoder) ? 'global.util' : (global && global.window && global.window.TextEncoder) ? 'global.window' : false
let textDecoderPath = (window && window.TextDecoder) ? 'window' : (util && util.TextDecoder) ? 'util' : (global && global.TextDecoder) ? 'global' : (global && global.util && global.util.TextDecoder) ? 'global.util' : (global && global.window && global.window.TextDecoder) ? 'global.window' : false