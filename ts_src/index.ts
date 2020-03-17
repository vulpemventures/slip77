const typeforce = require('typeforce');

import { hmacSHA256, hmacSHA512 } from './crypto';

const DOMAIN = Buffer.from('Symmetric key seed');
const LABEL = Buffer.from('SLIP-0077');
const PREFIX = Buffer.alloc(1, 0);

export class Slip77 {
  static fromMasterBlindingKey(_key: Buffer | string): Slip77 {
    typeforce(typeforce.anyOf('Buffer', 'String'), _key);
    const key = Buffer.isBuffer(_key) ? _key : Buffer.from(_key, 'hex');
    if (key.length !== 32) throw new TypeError('Invalid key length');
    const seed = Buffer.alloc(32, 0);
    const node = new Slip77(seed);
    const masterKey = Buffer.concat([seed, key]);
    node._data = masterKey;
    node._masterKey = masterKey;
    return node;
  }

  _data: Buffer;
  _masterKey: Buffer | undefined;

  constructor(_seed: Buffer | string) {
    typeforce(typeforce.anyOf('Buffer', 'String'), _seed);
    const seed = Buffer.isBuffer(_seed) ? _seed : Buffer.from(_seed, 'hex');
    this._data = hmacSHA512(DOMAIN, [seed]);
  }

  masterBlindingKey(): Buffer {
    if (this._masterKey !== undefined) return this._masterKey.slice(32);
    if (this._data === undefined) throw new Error('Seed not set');
    this._masterKey = hmacSHA512(this._data.slice(0, 32), [PREFIX, LABEL]);
    return this._masterKey.slice(32);
  }

  deriveBlindingKey(_script: Buffer | string): Buffer {
    typeforce(typeforce.anyOf('Buffer', 'String'), _script);
    if (this._masterKey === undefined) throw new Error('Master key not set');
    const script = Buffer.isBuffer(_script)
      ? _script
      : Buffer.from(_script, 'hex');
    return hmacSHA256(this._masterKey.slice(32), [script]);
  }
}
