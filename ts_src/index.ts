const ecc = require('tiny-secp256k1');
const typeforce = require('typeforce');

import { hmacSHA256, hmacSHA512 } from './crypto';

const DOMAIN = Buffer.from('Symmetric key seed');
const LABEL = Buffer.from('SLIP-0077');
const PREFIX = Buffer.alloc(1, 0);

export interface Slip77Interface {
  _masterKey: Buffer;
  masterBlindingKey(): Buffer;
  deriveBlindingPrivKey(script: Buffer | string): Buffer;
  deriveBlindingPubKey(script: Buffer | string): Buffer;
}

export class Slip77 implements Slip77Interface {
  static fromMasterBlindingKey(_key: Buffer | string): Slip77 {
    typeforce(typeforce.anyOf('Buffer', 'String'), _key);
    const key = Buffer.isBuffer(_key) ? _key : Buffer.from(_key, 'hex');
    if (key.length !== 32) throw new TypeError('Invalid key length');
    const seed = Buffer.alloc(32, 0);
    const node = new Slip77(seed);
    const masterKey = Buffer.concat([seed, key]);
    node._masterKey = masterKey;
    return node;
  }

  _masterKey: Buffer;

  constructor(_seed: Buffer | string) {
    typeforce(typeforce.anyOf('Buffer', 'String'), _seed);
    const seed = Buffer.isBuffer(_seed) ? _seed : Buffer.from(_seed, 'hex');
    const root = hmacSHA512(DOMAIN, [seed]);
    this._masterKey = hmacSHA512(root.slice(0, 32), [PREFIX, LABEL]);
  }

  masterBlindingKey(): Buffer {
    return this._masterKey.slice(32);
  }

  deriveBlindingPrivKey(_script: Buffer | string): Buffer {
    typeforce(typeforce.anyOf('Buffer', 'String'), _script);
    const script = Buffer.isBuffer(_script)
      ? _script
      : Buffer.from(_script, 'hex');
    return hmacSHA256(this._masterKey.slice(32), [script]);
  }

  deriveBlindingPubKey(_script: Buffer | string): Buffer {
    const privkey = this.deriveBlindingPrivKey(_script);
    return ecc.pointFromScalar(privkey);
  }
}
