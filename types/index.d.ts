/// <reference types="node" />
export interface Slip77Interface {
    _masterKey: Buffer;
    masterBlindingKey(): Buffer;
    deriveBlindingKey(script: Buffer | string): Buffer;
}
export declare class Slip77 implements Slip77Interface {
    static fromMasterBlindingKey(_key: Buffer | string): Slip77;
    _masterKey: Buffer;
    constructor(_seed: Buffer | string);
    masterBlindingKey(): Buffer;
    deriveBlindingKey(_script: Buffer | string): Buffer;
}
