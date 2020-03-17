const typeforce = require('typeforce');

import { hmacSHA256, hmacSHA512 } from './crypto';

const DOMAIN = Buffer.from('Symmetryc key seed');
const LABEL = Buffer.from('SLIP-0077');

export class Slip77 {
  private _seed: Buffer;
  private _masterBlindingKey: Buffer | undefined;

  constructor(seed: Buffer | string) {
    typeforce(typeforce.Buffer, seed);
    this._seed = Buffer.isBuffer(seed) ? seed : Buffer.from(seed, 'hex');
    this._masterBlindingKey = undefined;
  }

  masterBlindingKey(): Buffer {
    if (this._masterBlindingKey === undefined) {
      const root = hmacSHA512(DOMAIN, this._seed);
      console.log('root', root.slice(32).toString('hex'), root.length);
      this._masterBlindingKey = hmacSHA512(root, LABEL);
    }

    return this._masterBlindingKey;
  }

  deriveBlindingKey(script: Buffer): Buffer {
    typeforce(typeforce.Buffer, script);
    if (this._masterBlindingKey === undefined)
      throw new Error('Master blinding key is not set');

    return hmacSHA256(this._masterBlindingKey, script);
  }
}
