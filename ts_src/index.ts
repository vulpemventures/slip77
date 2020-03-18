const ecc = require('tiny-secp256k1');
const typeforce = require('typeforce');

import { hmacSHA256, hmacSHA512 } from './crypto';

const DOMAIN = Buffer.from('Symmetric key seed');
const LABEL = Buffer.from('SLIP-0077');
const PREFIX = Buffer.alloc(1, 0);

export interface Slip77Interface {
  masterKey: Buffer;
  extra?: Buffer;
  script?: Buffer;
  privateKey?: Buffer;
  publicKey?: Buffer;
  derive(script: Buffer | string): Slip77Interface;
}

export class Slip77 implements Slip77Interface {
  constructor(
    private _masterKey: Buffer,
    private _extra: Buffer | undefined,
    private _script: Buffer | undefined,
    private _privateKey: Buffer | undefined,
    private _publicKey: Buffer | undefined,
  ) {
    typeforce(typeforce.BufferN(32), _masterKey);
  }

  get masterKey(): Buffer {
    return this._masterKey;
  }

  get extra(): Buffer | undefined {
    return this._extra;
  }

  get script(): Buffer | undefined {
    return this._script;
  }

  get privateKey(): Buffer | undefined {
    return this._privateKey;
  }

  get publicKey(): Buffer | undefined {
    return this._publicKey;
  }

  derive(script: Buffer | string): Slip77Interface {
    return deriveLocal(this.masterKey, this.extra, script);
  }
}

export function fromMasterBlindingKey(key: Buffer | string): Slip77Interface {
  typeforce(typeforce.anyOf('Buffer', 'String'), key);
  const masterKey = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  return new Slip77(masterKey, undefined, undefined, undefined, undefined);
}

export function fromSeed(_seed: Buffer | string): Slip77Interface {
  typeforce(typeforce.anyOf('Buffer', 'String'), _seed);
  const seed = Buffer.isBuffer(_seed) ? _seed : Buffer.from(_seed, 'hex');
  const root = hmacSHA512(DOMAIN, [seed]);
  const masterKey = hmacSHA512(root.slice(0, 32), [PREFIX, LABEL]);
  return new Slip77(
    masterKey.slice(32),
    masterKey.slice(0, 32),
    undefined,
    undefined,
    undefined,
  );
}

function deriveLocal(
  masterKey: Buffer,
  extra: Buffer | undefined,
  script: Buffer | string,
): Slip77Interface {
  typeforce(
    {
      masterKey: typeforce.BufferN(32),
      script: typeforce.anyOf('Buffer', 'String'),
    },
    { masterKey, script },
  );
  const _script = Buffer.isBuffer(script) ? script : Buffer.from(script, 'hex');
  const derivedPrivKey = hmacSHA256(masterKey, [_script]);
  const derivedPubKey = ecc.pointFromScalar(derivedPrivKey);
  return new Slip77(masterKey, extra, _script, derivedPrivKey, derivedPubKey);
}
