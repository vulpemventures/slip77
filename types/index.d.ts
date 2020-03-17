/// <reference types="node" />
export declare class Slip77 {
    private _seed;
    private _masterBlindingKey;
    constructor(seed: Buffer | string);
    masterBlindingKey(): Buffer;
    deriveBlindingKey(script: Buffer): Buffer;
}
