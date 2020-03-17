/// <reference types="node" />
export declare class Slip77 {
    private _data;
    private _masterKey;
    constructor(_seed: Buffer | string);
    masterBlindingKey(): Buffer;
    deriveBlindingKey(_script: Buffer | string): Buffer;
}
