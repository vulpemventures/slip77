/// <reference types="node" />
export interface Slip77Interface {
    masterKey: Buffer;
    extra?: Buffer;
    script?: Buffer;
    privateKey?: Buffer;
    publicKey?: Buffer;
    derive(script: Buffer | string): Slip77Interface;
}
export declare class Slip77 implements Slip77Interface {
    private _masterKey;
    private _extra;
    private _script;
    private _privateKey;
    private _publicKey;
    constructor(_masterKey: Buffer, _extra: Buffer | undefined, _script: Buffer | undefined, _privateKey: Buffer | undefined, _publicKey: Buffer | undefined);
    readonly masterKey: Buffer;
    readonly extra: Buffer | undefined;
    readonly script: Buffer | undefined;
    readonly privateKey: Buffer | undefined;
    readonly publicKey: Buffer | undefined;
    derive(script: Buffer | string): Slip77Interface;
}
export declare function fromMasterBlindingKey(key: Buffer | string): Slip77Interface;
export declare function fromBip39Seed(_seed: Buffer | string): Slip77Interface;
