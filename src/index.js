'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const typeforce = require('typeforce');
const crypto_1 = require('./crypto');
const DOMAIN = Buffer.from('Symmetric key seed');
const LABEL = Buffer.from('SLIP-0077');
const PREFIX = Buffer.alloc(1, 0);
function SLIP77Factory(ecc) {
  return {
    fromSeed(seed) {
      typeforce(typeforce.anyOf('Buffer', 'String'), seed);
      const slip77seed = Buffer.isBuffer(seed)
        ? seed
        : Buffer.from(seed, 'hex');
      const root = crypto_1.hmacSHA512(DOMAIN, [slip77seed]);
      const masterKey = crypto_1.hmacSHA512(root.slice(0, 32), [PREFIX, LABEL]);
      return new Slip77(
        masterKey.slice(32),
        masterKey.slice(0, 32),
        undefined,
        undefined,
        undefined,
        ecc,
      );
    },
    fromMasterBlindingKey(key) {
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
exports.SLIP77Factory = SLIP77Factory;
class Slip77 {
  constructor(_masterKey, _extra, _script, _privateKey, _publicKey, _ecc) {
    this._masterKey = _masterKey;
    this._extra = _extra;
    this._script = _script;
    this._privateKey = _privateKey;
    this._publicKey = _publicKey;
    this._ecc = _ecc;
    typeforce(typeforce.BufferN(32), _masterKey);
  }
  get masterKey() {
    return this._masterKey;
  }
  get extra() {
    return this._extra;
  }
  get script() {
    return this._script;
  }
  get privateKey() {
    return this._privateKey;
  }
  get publicKey() {
    return this._publicKey;
  }
  derive(script) {
    return deriveLocal(this.masterKey, this.extra, script, this._ecc);
  }
}
function deriveLocal(masterKey, extra, script, ecc) {
  const _script = Buffer.isBuffer(script) ? script : Buffer.from(script, 'hex');
  const derivedPrivKey = crypto_1.hmacSHA256(masterKey, [_script]);
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
