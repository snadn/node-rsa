/*
 * RSA Encryption / Decryption with PKCS1 v2 Padding.
 * 
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

/*
 * Node.js adaptation
 * long message support implementation
 * signing/verifying
 *
 * 2014 rzcoder
 */

var _ = require('../utils')._;
var BigInteger = require('./jsbn.js');
var utils = require('../utils.js');
var encryptionSchemeProvider = require('../schemes/oaep.browser.js');

exports.BigInteger = BigInteger;
module.exports.Key = (function () {
    /**
     * RSA key constructor
     *
     * n - modulus
     * e - publicExponent
     * d - privateExponent
     * p - prime1
     * q - prime2
     * dmp1 - exponent1 -- d mod (p1)
     * dmq1 - exponent2 -- d mod (q-1)
     * coeff - coefficient -- (inverse of q) mod p
     */
    function RSAKey() {
        this.n = null;
        this.e = 0;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.coeff = null;
    }

    RSAKey.prototype.setOptions = function (options) {

        this.encryptionScheme = encryptionSchemeProvider.makeScheme(this, options);

        this.encryptEngine = (function(keyPair, options) {
            return {
                encrypt: function (buffer, usePrivate) {
                    var m, c;

                    m = new BigInteger(keyPair.encryptionScheme.encPad(buffer));
                    c = keyPair.$doPublic(m);

                    return c.toBuffer(keyPair.getEncryptedDataLength());
                }
            };
        })(this, options);

    };

    /**
     * Set the public key fields N and e from hex strings
     * @param N
     * @param E
     */
    RSAKey.prototype.setPublic = function (N, E) {
        if (N && E && N.length > 0 && (_.isNumber(E) || E.length > 0)) {
            this.n = new BigInteger(N);
            this.e = _.isNumber(E) ? E : utils.get32IntFromBuffer(E, 0);
            this.$$recalculateCache();
        } else {
            throw Error("Invalid RSA public key");
        }
    };

    /**
     * private
     * Perform raw public operation on "x": return x^e (mod n)
     *
     * @param x
     * @returns {*}
     */
    RSAKey.prototype.$doPublic = function (x) {
        return x.modPowInt(this.e, this.n);
    };

    /**
     * Return the PKCS#1 RSA encryption of buffer
     * @param buffer {Buffer}
     * @returns {Buffer}
     */
    RSAKey.prototype.encrypt = function (buffer, usePrivate) {
        var buffers = [];
        var results = [];
        var bufferSize = buffer.length;
        var buffersCount = Math.ceil(bufferSize / this.getMaxMessageLength()) || 1; // total buffers count for encrypt
        var dividedSize = Math.ceil(bufferSize / buffersCount || 1); // each buffer size

        if (buffersCount == 1) {
            buffers.push(buffer);
        } else {
            for (var bufNum = 0; bufNum < buffersCount; bufNum++) {
                buffers.push(buffer.slice(bufNum * dividedSize, (bufNum + 1) * dividedSize));
            }
        }

        for (var i = 0; i < buffers.length; i++) {
            results.push(this.encryptEngine.encrypt(buffers[i], usePrivate));
        }

        return Buffer.concat(results);
    };

    RSAKey.prototype.getEncryptedDataLength = function() {
        return this.cache.keyByteLength;
    };
    RSAKey.prototype.getMaxMessageLength = function() {
        return this.encryptionScheme.maxMessageLength();
    };

    /**
     * Caching key data
     */
    RSAKey.prototype.$$recalculateCache = function () {
        this.cache = this.cache || {};
        // Bit & byte length
        this.cache.keyBitLength = this.n.bitLength();
        this.cache.keyByteLength = (this.cache.keyBitLength + 6) >> 3;
    };

    return RSAKey;
})();

