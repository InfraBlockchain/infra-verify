import { Resolvable } from 'did-resolver';
import { ConfigurationOptions } from 'infra-did-resolver';
export interface VerifierConfig {
    resolver?: Resolvable;
    networkConfig: ConfigurationOptions;
    did: string;
    knownIssuer: string[];
}
export declare type JWT = string;
export declare type DID = string;
export default class Verifier {
    resolver: Resolvable;
    challenge: string;
    did: string;
    knownIssuer: string[];
    constructor(config: VerifierConfig);
    ready(): {
        challenge: string;
        aud: string;
    };
    private generateChallenge;
    isValidVP(vp: JWT): Promise<boolean>;
    isValidVC(vc: JWT, holder?: DID): Promise<boolean>;
    isRevoked(did: DID): Promise<boolean>;
    isKnownIssuer(issuer: DID): boolean;
}
