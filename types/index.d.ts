/// <reference types="node" />
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
export declare function SLIP77Factory(ecc: TinySecp256k1Interface): SLIP77API;
