'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const ecc = require('tiny-secp256k1');
const typeforce = require('typeforce');
const crypto_1 = require('./crypto');
const DOMAIN = Buffer.from('Symmetric key seed');
const LABEL = Buffer.from('SLIP-0077');
const PREFIX = Buffer.alloc(1, 0);
class Slip77 {
  constructor(_masterKey, _extra, _script, _privateKey, _publicKey) {
    this._masterKey = _masterKey;
    this._extra = _extra;
    this._script = _script;
    this._privateKey = _privateKey;
    this._publicKey = _publicKey;
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
    return deriveLocal(this.masterKey, this.extra, script);
  }
}
exports.Slip77 = Slip77;
function fromMasterBlindingKey(key) {
  typeforce(typeforce.anyOf('Buffer', 'String'), key);
  const masterKey = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
  return new Slip77(masterKey, undefined, undefined, undefined, undefined);
}
exports.fromMasterBlindingKey = fromMasterBlindingKey;
function fromSeed(_seed) {
  typeforce(typeforce.anyOf('Buffer', 'String'), _seed);
  const seed = Buffer.isBuffer(_seed) ? _seed : Buffer.from(_seed, 'hex');
  const root = crypto_1.hmacSHA512(DOMAIN, [seed]);
  const masterKey = crypto_1.hmacSHA512(root.slice(0, 32), [PREFIX, LABEL]);
  return new Slip77(
    masterKey.slice(32),
    masterKey.slice(0, 32),
    undefined,
    undefined,
    undefined,
  );
}
exports.fromSeed = fromSeed;
function deriveLocal(masterKey, extra, script) {
  typeforce(
    {
      masterKey: typeforce.BufferN(32),
      script: typeforce.anyOf('Buffer', 'String'),
    },
    { masterKey, script },
  );
  const _script = Buffer.isBuffer(script) ? script : Buffer.from(script, 'hex');
  const derivedPrivKey = crypto_1.hmacSHA256(masterKey, [_script]);
  const derivedPubKey = ecc.pointFromScalar(derivedPrivKey);
  return new Slip77(masterKey, extra, _script, derivedPrivKey, derivedPubKey);
}
