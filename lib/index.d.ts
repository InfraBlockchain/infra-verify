import { Resolvable } from 'did-resolver';
import { ConfigurationOptions } from 'infra-did-resolver';
export interface VerifierConfig {
    resolver?: Resolvable;
    networkConfig: ConfigurationOptions;
    did: string;
    knownIssuers: Issuer[];
}
export declare type JWT = string;
export declare type DID = string;
export declare type Issuer = {
    id: string;
    did: DID;
};
export default class Verifier {
    resolver: Resolvable;
    challenge: string;
    did: string;
    knownIssuers: Issuer[];
    constructor(config: VerifierConfig);
    ready(): {
        challenge: string;
        aud: string;
    };
    private generateChallenge;
    getVPClaims(vp: JWT): any;
    getVCClaims(vc: JWT): any;
    isValid(jwt: JWT): Promise<boolean>;
    isValidVP(vp: JWT): Promise<boolean>;
    isValidVC(vc: JWT, holder?: DID): Promise<boolean>;
    isRevoked(did: DID): Promise<boolean>;
    isKnownIssuer(issuer: DID): boolean;
}
