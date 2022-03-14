const typeforce = require('typeforce');

import { hmacSHA256, hmacSHA512 } from './crypto';

const DOMAIN = Buffer.from('Symmetric key seed');
const LABEL = Buffer.from('SLIP-0077');
const PREFIX = Buffer.alloc(1, 0);

export interface SLIP77API {
  fromSeed(seed: Buffer | string): Slip77Interface;
  fromMasterBlindingKey(masterBlindingKey: Buffer | string): Slip77Interface;
}

export interface Slip77Interface {
  masterKey: Buffer;
  extra?: Buffer;
  script?: Buffer;
  privateKey?: Buffer;
  publicKey?: Buffer;
  derive(script: Buffer | string): Slip77Interface;
}

export interface TinySecp256k1Interface {
  pointFromScalar(d: Uint8Array, compressed?: boolean): Uint8Array | null;
}

export function SLIP77Factory(ecc: TinySecp256k1Interface): SLIP77API {
  return {
    fromSeed(seed: Buffer | string): Slip77Interface {
      typeforce(typeforce.anyOf('Buffer', 'String'), seed);
      const slip77seed = Buffer.isBuffer(seed)
        ? seed
        : Buffer.from(seed, 'hex');
      const root = hmacSHA512(DOMAIN, [slip77seed]);
      const masterKey = hmacSHA512(root.slice(0, 32), [PREFIX, LABEL]);
      return new Slip77(
        masterKey.slice(32),
        masterKey.slice(0, 32),
        undefined,
        undefined,
        undefined,
        ecc,
      );
    },
    fromMasterBlindingKey(key: Buffer | string): Slip77Interface {
      typeforce(typeforce.anyOf('Buffer', 'String'), key);
      const masterKey = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
      return new Slip77(
        masterKey,
        undefined,
        undefined,
        undefined,
        undefined,
        ecc,
      );
    },
  };
}

class Slip77 implements Slip77Interface {
  constructor(
    private _masterKey: Buffer,
    private _extra: Buffer | undefined,
    private _script: Buffer | undefined,
    private _privateKey: Buffer | undefined,
    private _publicKey: Buffer | undefined,
    private _ecc: TinySecp256k1Interface,
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
    return deriveLocal(this.masterKey, this.extra, script, this._ecc);
  }
}

function deriveLocal(
  masterKey: Buffer,
  extra: Buffer | undefined,
  script: Buffer | string,
  ecc: TinySecp256k1Interface,
): Slip77Interface {
  const _script = Buffer.isBuffer(script) ? script : Buffer.from(script, 'hex');
  const derivedPrivKey = hmacSHA256(masterKey, [_script]);
  const derivedPubKey = ecc.pointFromScalar(derivedPrivKey);
  return new Slip77(
    masterKey,
    extra,
    _script,
    derivedPrivKey,
    derivedPubKey ? Buffer.from(derivedPubKey) : undefined,
    ecc,
  );
}
