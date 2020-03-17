# slip77

[![Build Status](https://travis-ci.org/vulpemventures/slip77.png?branch=master)](https://travis-ci.org/vulpemventures/slip77)

[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

A [SLIP-77](https://github.com/satoshilabs/slips/blob/master/slip-0077.md) compatible library written in TypeScript with transpiled JavaScript committed to git.

## Example

- [Generate a master blinding key from BIP39 seed](./tests/index.js#L20)
- [Derive a child blinding key from master](./tests/index.js#L29)

## LICENSE [MIT](LICENSE)

A derivation (and extraction for modularity) of the `HDWallet`/`HDNode` written and tested by [liquidjs-lib](https://github.com/vulpemventures/liquidjs-lib) contributors since 2020.
