/// <reference types="node" />
export interface Slip77Interface {
    _masterKey: Buffer;
    masterBlindingKey(): Buffer;
    deriveBlindingPrivKey(script: Buffer | string): Buffer;
    deriveBlindingPubKey(script: Buffer | string): Buffer;
}
export declare class Slip77 implements Slip77Interface {
    static fromMasterBlindingKey(_key: Buffer | string): Slip77;
    _masterKey: Buffer;
    constructor(_seed: Buffer | string);
    masterBlindingKey(): Buffer;
    deriveBlindingPrivKey(_script: Buffer | string): Buffer;
    deriveBlindingPubKey(_script: Buffer | string): Buffer;
}
