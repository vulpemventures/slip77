'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeforce = require('typeforce');
const crypto_1 = require('./crypto');
const DOMAIN = Buffer.from('Symmetryc key seed');
const LABEL = Buffer.from('SLIP-0077');
class Slip77 {
  constructor(seed) {
    typeforce(typeforce.Buffer, seed);
    this._seed = Buffer.isBuffer(seed) ? seed : Buffer.from(seed, 'hex');
    this._masterBlindingKey = undefined;
  }
  masterBlindingKey() {
    if (this._masterBlindingKey === undefined) {
      const root = crypto_1.hmacSHA512(DOMAIN, this._seed);
      console.log('root', root.slice(32).toString('hex'), root.length);
      this._masterBlindingKey = crypto_1.hmacSHA512(root, LABEL);
    }
    return this._masterBlindingKey;
  }
  deriveBlindingKey(script) {
    typeforce(typeforce.Buffer, script);
    if (this._masterBlindingKey === undefined)
      throw new Error('Master blinding key is not set');
    return crypto_1.hmacSHA256(this._masterBlindingKey, script);
  }
}
exports.Slip77 = Slip77;
