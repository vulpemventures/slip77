const bip39 = require('bip39');
const test = require('tape');
const preFixtures = require('./fixtures');
const { Slip77 } = require('../src/');

const initBuffers = object =>
  JSON.parse(JSON.stringify(object), (_, value) => {
    const regex = new RegExp(/^Buffer.from\(['"](.*)['"], ['"](.*)['"]\)$/);
    const result = regex.exec(value);
    if (!result) return value;

    const data = result[1];
    const encoding = result[2];

    return Buffer.from(data, encoding);
  });

const fixtures = initBuffers(preFixtures);

fixtures.valid.masterBlindingKey.forEach(f => {
  test('masterBlindingKey from mnemonic', t => {
    const seed = bip39.mnemonicToSeedSync(f.mnemonic);
    const slip77Node = new Slip77(seed);
    t.same(slip77Node.masterBlindingKey().toString('hex'), f.expected);
    t.end();
  });
});

fixtures.valid.deriveBlindingKey.forEach(f => {
  test('deriveBlindingKey from master', t => {
    const slip77Node = Slip77.fromMasterBlindingKey(f.masterKey);
    t.same(slip77Node.masterBlindingKey(), f.masterKey);
    t.same(slip77Node.deriveBlindingKey(f.script).toString('hex'), f.expected);
    t.end();
  });
});

fixtures.invalid.fromMasterBlindingKey.forEach(f => {
  test('fromMasterBlindingKey throws', t => {
    t.throws(() => {
      Slip77.fromMasterBlindingKey(f.masterKey);
    }, new RegExp(f.exception));
    t.end();
  });
});
