const hash = require('./hash');
const assert = require('assert');
const keyUtils = require('./key_utils');
const PublicKey = require('./key_public');
const PrivateKey = require('./key_private');
const secp256k1 = require('secp256k1');

module.exports = Signature

function Signature(rs, i) {
    assert.equal(rs != null, true, 'Missing parameter');
    assert.equal(i != null, true, 'Missing parameter');
    if(!Buffer.isBuffer(rs)) {
        throw new TypeError('Invalid signature')
    }
    assert.equal(rs.length, 64, 'Signature incorrect length');

    /**
        Verify signed data.

        @arg {String|Buffer} data - full data
        @arg {pubkey|PublicKey} pubkey - EOSKey..
        @arg {String} [encoding = 'utf8'] - data encoding (if data is a string)

        @return {boolean}
    */
    function verify(data, pubkey, encoding = 'utf8') {
        if(typeof data === 'string') {
            data = Buffer.from(data, encoding)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)
        return verifyHash(data, pubkey)
    }

    /**
        Verify a buffer of exactally 32 bytes in size (sha256(text))

        @arg {String|Buffer} dataSha256 - 32 byte buffer or string
        @arg {String|PublicKey} pubkey - EOSKey..
        @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

        @return {boolean}
    */
    function verifyHash(dataSha256, pubkey, encoding = 'hex') {
        if(typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, encoding)
        }
        if(dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256))
            throw new Error("dataSha256: 32 bytes required")

        const publicKey = PublicKey(pubkey)
        assert(publicKey, 'pubkey required')

        return secp256k1.verify(dataSha256, rs, publicKey.Q);
    };

    /** @deprecated

        Verify hex data by converting to a buffer then hashing.

        @return {boolean}
    */
    function verifyHex(hex, pubkey) {
        console.log('Deprecated: use verify(data, pubkey, "hex")');

        const buf = Buffer.from(hex, 'hex');
        return verify(buf, pubkey);
    };

    /**
        Recover the public key used to create this signature using full data.

        @arg {String|Buffer} data - full data
        @arg {String} [encoding = 'utf8'] - data encoding (if string)

        @return {PublicKey}
    */
    function recover(data, encoding = 'utf8') {
        if(typeof data === 'string') {
            data = Buffer.from(data, encoding)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)

        return recoverHash(data)
    };

    /**
        @arg {String|Buffer} dataSha256 - sha256 hash 32 byte buffer or hex string
        @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

        @return {PublicKey}
    */
    function recoverHash(dataSha256, encoding = 'hex') {
        if(typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, encoding)
        }
        if(dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256)) {
            throw new Error("dataSha256: 32 byte String or buffer requred")
        }

        let i2 = i;
        i2 -= 27;
        i2 = i2 & 3;
        return PublicKey.fromBuffer(secp256k1.recover(dataSha256, rs, i2));
    };

    function toBuffer() {
        var buf;
        buf = new Buffer(65);
        buf.writeUInt8(i, 0);
        rs.copy(buf, 1);
        return buf;
    };

    function toHex() {
        return toBuffer().toString("hex");
    };

    let signatureCache

    function toString() {
      if(signatureCache) {
          return signatureCache
      }
      signatureCache = 'SIG_K1_' + keyUtils.checkEncode(toBuffer(), 'K1')
      return signatureCache
    }

    return {
        rs, i,
        toBuffer,
        verify,
        verifyHash,
        verifyHex,// deprecated
        recover,
        recoverHash,
        toHex,
        toString,

        /** @deprecated use verify (same arguments and return) */
        verifyBuffer: (...args) => {
          console.log('Deprecated: use signature.verify instead (same arguments)');
          return verify(...args)
        },

        /** @deprecated use recover (same arguments and return) */
        recoverPublicKey: (...args) => {
          console.log('Deprecated: use signature.recover instead (same arguments)');
          return recover(...args)
        },

        /** @deprecated use recoverHash (same arguments and return) */
        recoverPublicKeyFromBuffer: (...args) => {
          console.log('Deprecated: use signature.recoverHash instead (same arguments)');
          return recoverHash(...args)
        }
    }
}

/**
    Hash and sign arbitrary data.

    @arg {string|Buffer} data - full data
    @arg {wif|PrivateKey} privateKey
    @arg {String} [encoding = 'utf8'] - data encoding (if string)

    @return {Signature}
*/
Signature.sign = function(data, privateKey, encoding = 'utf8') {
    if(typeof data === 'string') {
        data = Buffer.from(data, encoding)
    }
    assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
    data = hash.sha256(data)
    return Signature.signHash(data, privateKey)
}

/**
    Sign a buffer of exactally 32 bytes in size (sha256(text))

    @arg {string|Buffer} dataSha256 - 32 byte buffer or string
    @arg {wif|PrivateKey} privateKey
    @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

    @return {Signature}
*/
Signature.signHash = function(dataSha256, privateKey, encoding = 'hex') {
    if(typeof dataSha256 === 'string') {
        dataSha256 = Buffer.from(dataSha256, encoding)
    }
    if( dataSha256.length !== 32 || ! Buffer.isBuffer(dataSha256) )
        throw new Error("dataSha256: 32 byte buffer requred")

    privateKey = PrivateKey(privateKey)
    assert(privateKey, 'privateKey required')

    var der, secpsig, i, lenR, lenS, nonce, r, s;
    i = null;
    nonce = 0;

    while (true) {
      secpsig = secp256k1.sign(dataSha256, privateKey.toBuffer(), {data: hash.sha256(Buffer.concat([dataSha256, new Buffer(nonce++)]))});
      der = secp256k1.signatureExport(secpsig.signature);
      lenR = der[3];
      lenS = der[5 + lenR];
      if (lenR === 32 && lenS === 32) {
        i = secpsig.recovery;
        i += 4;  // compressed
        i += 27; // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
        break;
      }
      if (nonce % 10 === 0) {
        console.log("WARN: " + nonce + " attempts to find canonical signature");
      }
    }
    return Signature(secpsig.signature, i);
};

Signature.fromBuffer = function(buf) {
    var i, r, s;
    assert(Buffer.isBuffer(buf), 'Buffer is required')
    assert.equal(buf.length, 65, 'Invalid signature length');
    i = buf.readUInt8(0);
    assert.equal(i - 27, i - 27 & 7, 'Invalid signature parameter');
    return Signature(buf.slice(1), i);
};

Signature.fromHex = function(hex) {
    return Signature.fromBuffer(Buffer.from(hex, "hex"));
};

/**
    @arg {string} signature - like SIG_K1_base58signature..
    @return {Signature} or `null` (invalid)
*/
Signature.fromString = function(signature) {
    try {
        return Signature.fromStringOrThrow(signature)
    } catch (e) {
        return null;
    }
}

/**
    @arg {string} signature - like SIG_K1_base58signature..
    @throws {Error} invalid
    @return {Signature}
*/
Signature.fromStringOrThrow = function(signature) {
    assert.equal(typeof signature, 'string', 'signature')
    const match = signature.match(/^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)
    assert(match != null && match.length === 3, 'Expecting signature like: SIG_K1_base58signature..')
    const [, keyType, keyString] = match
    assert.equal(keyType, 'K1', 'K1 signature expected')
    return Signature.fromBuffer(keyUtils.checkDecode(keyString, keyType))
}

/**
    @arg {String|Signature} o - hex string
    @return {Signature}
*/
Signature.from = (o) => {
    const signature = o ?
        (o.r && o.s && o.i) ? o :
        typeof o === 'string' && o.length === 130 ? Signature.fromHex(o) :
        typeof o === 'string' && o.length !== 130 ? Signature.fromStringOrThrow(o) :
        Buffer.isBuffer(o) ? Signature.fromBuffer(o) :
        null : o/*null or undefined*/

    if(!signature) {
        throw new TypeError('signature should be a hex string or buffer')
    }
    return signature
}
