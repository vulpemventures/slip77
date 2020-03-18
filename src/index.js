'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const ecc = require('tiny-secp256k1');
const typeforce = require('typeforce');
const crypto_1 = require('./crypto');
const DOMAIN = Buffer.from('Symmetric key seed');
const LABEL = Buffer.from('SLIP-0077');
const PREFIX = Buffer.alloc(1, 0);
class Slip77 {
  static fromMasterBlindingKey(_key) {
    typeforce(typeforce.anyOf('Buffer', 'String'), _key);
    const key = Buffer.isBuffer(_key) ? _key : Buffer.from(_key, 'hex');
    if (key.length !== 32) throw new TypeError('Invalid key length');
    const seed = Buffer.alloc(32, 0);
    const node = new Slip77(seed);
    const masterKey = Buffer.concat([seed, key]);
    node._masterKey = masterKey;
    return node;
  }
  constructor(_seed) {
    typeforce(typeforce.anyOf('Buffer', 'String'), _seed);
    const seed = Buffer.isBuffer(_seed) ? _seed : Buffer.from(_seed, 'hex');
    const root = crypto_1.hmacSHA512(DOMAIN, [seed]);
    this._masterKey = crypto_1.hmacSHA512(root.slice(0, 32), [PREFIX, LABEL]);
  }
  masterBlindingKey() {
    return this._masterKey.slice(32);
  }
  deriveBlindingPrivKey(_script) {
    typeforce(typeforce.anyOf('Buffer', 'String'), _script);
    const script = Buffer.isBuffer(_script)
      ? _script
      : Buffer.from(_script, 'hex');
    return crypto_1.hmacSHA256(this._masterKey.slice(32), [script]);
  }
  deriveBlindingPubKey(_script) {
    const privkey = this.deriveBlindingPrivKey(_script);
    return ecc.pointFromScalar(privkey);
  }
}
exports.Slip77 = Slip77;
