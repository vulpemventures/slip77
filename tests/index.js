const bip39 = require('bip39');
const test = require('tape');
const preFixtures = require('./fixtures');
const slip77 = require('../src/');

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

fixtures.valid.fromSeed.forEach(f => {
  test('fromSeed', t => {
    const seed = bip39.mnemonicToSeedSync(f.mnemonic);
    const node1 = slip77.fromSeed(seed);
    const node2 = slip77.fromSeed(seed.toString('hex'));
    t.same(node1.masterKey.toString('hex'), f.expected);
    t.same(node2.masterKey.toString('hex'), f.expected);
    t.end();
  });
});

fixtures.valid.fromMasterBlindingKey.forEach(f => {
  test('fromMasterBlindingKey', t => {
    const slip77Node = slip77.fromMasterBlindingKey(f.masterKey);
    t.same(slip77Node.masterKey.toString('hex'), f.masterKey);
    t.end();
  });
});

fixtures.valid.derive.forEach(f => {
  test('derive', t => {
    const master = slip77.fromMasterBlindingKey(f.masterKey);
    const derived = master.derive(f.script);
    t.same(derived.privateKey.toString('hex'), f.expectedPrivKey);
    t.same(derived.publicKey.toString('hex'), f.expectedPubKey);
    t.end();
  });
});

fixtures.invalid.fromSeed.forEach(f => {
  test('fromSeed throws', t => {
    t.throws(() => {
      slip77.fromSeed(f.seed);
    }, new RegExp(f.exception));
    t.end();
  });
});

fixtures.invalid.fromMasterBlindingKey.forEach(f => {
  test('fromMasterBlindingKey throws', t => {
    t.throws(() => {
      slip77.fromMasterBlindingKey(f.masterKey);
    }, new RegExp(f.exception));
    t.end();
  });
});
