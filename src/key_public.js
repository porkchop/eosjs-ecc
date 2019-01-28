const assert = require('assert');
const ecurve = require('ecurve');
const BigInteger = require('bigi');
const secp256k1 = require('secp256k1');

const hash = require('./hash');
const keyUtils = require('./key_utils');

module.exports = PublicKey

/**
  @param {string|Buffer|PublicKey|ecurve.Point} public key
  @param {string} [pubkey_prefix = 'EOS']
*/
function PublicKey(Q, pubkey_prefix = 'EOS') {
    if(typeof Q === 'string') {
        const publicKey = PublicKey.fromString(Q, pubkey_prefix)
        assert(publicKey != null, 'Invalid public key')
        return publicKey
    } else if(typeof Q === 'object' && Buffer.isBuffer(Q.Q)) {
      return PublicKey(Q.Q)
    }


    if(!Buffer.isBuffer(Q)) {
        throw new TypeError('Invalid public key')
    }

    let compressed = Q.length === 33;

    function toBuffer(_compressed = compressed) {
        if(!_compressed && compressed) {
          return secp256k1.publicKeyConvert(Q, false);
        }
        return Q;
    }

    /** @todo rename to toStringLegacy
     * @arg {string} [pubkey_prefix = 'EOS'] - public key prefix
    */
    function toString(pubkey_prefix = 'EOS') {
      return pubkey_prefix + keyUtils.checkEncode(Q)
    }

    function toUncompressed() {
        return secp256k1.publicKeyConvert(Q, false);
    }

    /** @deprecated */
    function child( offset ) {
        console.error('Deprecated warning: PublicKey.child')

        assert(Buffer.isBuffer(offset), "Buffer required: offset")
        assert.equal(offset.length, 32, "offset length")

        offset = Buffer.concat([ toBuffer(), offset ])
        offset = hash.sha256( offset )
        return PublicKey.fromBuffer(secp256k1.secretKeyTweakAdd(Q, offset))
    }

    function toHex() {
        return Q.toString('hex');
    }

    return {
        Q,
        toString,
        // toStringLegacy,
        toUncompressed,
        toBuffer,
        child,
        toHex
    }
}

/**
  @param {string|Buffer|PublicKey|ecurve.Point} pubkey - public key
  @param {string} [pubkey_prefix = 'EOS']
*/
PublicKey.isValid = function(pubkey, pubkey_prefix = 'EOS') {
    try {
        PublicKey(pubkey, pubkey_prefix)
        return true
    } catch(e) {
        return false
    }
}

PublicKey.fromBinary = function(bin) {
    return PublicKey.fromBuffer(new Buffer(bin, 'binary'));
}

PublicKey.fromBuffer = function(buffer) {
    return PublicKey(buffer);
}

/**
    @arg {string} public_key - like PUB_K1_base58pubkey..
    @arg {string} [pubkey_prefix = 'EOS'] - public key prefix
    @return PublicKey or `null` (invalid)
*/
PublicKey.fromString = function(public_key, pubkey_prefix = 'EOS') {
    try {
        return PublicKey.fromStringOrThrow(public_key, pubkey_prefix)
    } catch (e) {
        return null;
    }
}

/**
    @arg {string} public_key - like PUB_K1_base58pubkey..
    @arg {string} [pubkey_prefix = 'EOS'] - public key prefix

    @throws {Error} if public key is invalid

    @return PublicKey
*/
PublicKey.fromStringOrThrow = function(public_key, pubkey_prefix = 'EOS') {
    assert.equal(typeof public_key, 'string', 'public_key')
    const match = public_key.match(/^PUB_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)
    if(match === null) {
      // legacy
      var prefix_match = new RegExp("^" + pubkey_prefix);
      if(prefix_match.test(public_key)) {
        public_key = public_key.substring(pubkey_prefix.length)
      }
      return PublicKey.fromBuffer(keyUtils.checkDecode(public_key))
    }
    assert(match.length === 3, 'Expecting public key like: PUB_K1_base58pubkey..')
    const [, keyType, keyString] = match
    assert.equal(keyType, 'K1', 'K1 private key expected')
    return PublicKey.fromBuffer(keyUtils.checkDecode(keyString, keyType))
}

PublicKey.fromHex = function(hex) {
    return PublicKey.fromBuffer(new Buffer(hex, 'hex'));
}

PublicKey.fromStringHex = function(hex) {
    return PublicKey.fromString(new Buffer(hex, 'hex'));
}
