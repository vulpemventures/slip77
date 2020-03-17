/// <reference types="node" />
export declare class Slip77 {
    static fromMasterBlindingKey(_key: Buffer | string): Slip77;
    _data: Buffer;
    _masterKey: Buffer | undefined;
    constructor(_seed: Buffer | string);
    masterBlindingKey(): Buffer;
    deriveBlindingKey(_script: Buffer | string): Buffer;
}
