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
    const node1 = new Slip77(seed);
    const node2 = new Slip77(seed.toString('hex'));
    t.same(node1.masterBlindingKey().toString('hex'), f.expected);
    t.same(node2.masterBlindingKey().toString('hex'), f.expected);
    t.end();
  });
});

fixtures.valid.deriveBlindingKey.forEach(f => {
  test('deriveBlindingKey from master', t => {
    const slip77Node = Slip77.fromMasterBlindingKey(f.masterKey);
    t.same(slip77Node.masterBlindingKey().toString('hex'), f.masterKey);
    t.same(
      slip77Node.deriveBlindingPrivKey(f.script).toString('hex'),
      f.expectedPrivKey,
    );
    t.same(
      slip77Node
        .deriveBlindingPubKey(Buffer.from(f.script, 'hex'))
        .toString('hex'),
      f.expectedPubKey,
    );
    t.end();
  });
});

fixtures.invalid.constructor.forEach(f => {
  test('constructor throws', t => {
    t.throws(() => {
      new Slip77(f.seed);
    }, new RegExp(f.exception));
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
