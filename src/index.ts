// import { decodeJWT } from 'did-jwt';
import { verifyPresentation, verifyCredential, VerifiablePresentation, VerifiableCredential } from 'did-jwt-vc';
import { Resolver, Resolvable } from 'did-resolver';
import { getResolver, ConfigurationOptions } from 'infra-did-resolver';
import InfraDID from 'infra-did-js';

export interface VerifierConfig {
    resolver?: Resolvable
    networkConfig: ConfigurationOptions
    did: string
    knownIssuer: string[]
}

export type JWT = string
export type DID = string

export default class Verifier {
    public resolver: Resolvable
    public challenge: string
    public did: string
    public knownIssuer: string[]

    constructor (config : VerifierConfig) {
        this.resolver = config.resolver ? config.resolver : new Resolver(getResolver(config.networkConfig));
        this.did = config.did ? config.did : InfraDID.createPubKeyDIDsecp256k1('01').did;
        this.knownIssuer = config.knownIssuer;
    }

    public ready() : { challenge: string, aud: string } {
        this.challenge = this.generateChallenge();
        return { challenge: this.challenge, aud: this.did };
    }

    private generateChallenge() : string {
        // use randomly generated DID as nonce for now
        return InfraDID.createPubKeyDIDsecp256k1('01').did;
    }

    // public getVPClaims(vp: JWT) : any {
    //     const vcList = decodeJWT(vp).payload.vp.verifiableCredential;
    //     return vcList.map((vc) => {
    //         return this.getVCClaims(vc);
    //     }).reduce((result, claims) => {
    //         return { ...claims, ...result }
    //     }, {});
    // }

    // public getVCClaims(vc: JWT) : any {
    //     return decodeJWT(vc).payload.vc.credentialSubject;
    // }

    // public async isValid(jwt: JWT) : Promise<boolean> {
    //     const decoded = decodeJWT(jwt);
    //     if (decoded.payload.vp) return this.isValidVP(jwt);
    //     else if (decoded.payload.vc) return this.isValidVC(jwt);
    //     else throw new Error (`Unsupported type`);
    // }

    public async isValidVP (vp: JWT) : Promise<boolean> {
        // verify VP has been issued to the verifier with correct challenge
        const verifiedPresentation = await verifyPresentation(vp, this.resolver, { challenge: this.challenge, audience: this.did })
        const vcList = verifiedPresentation.payload.vp.VerifiedCredential;
        const signer = verifiedPresentation.payload.signer;
        if (this.isRevoked(signer.did)) throw new Error (`Deactivated Presenter`);
        return vcList.map((vc) => {
            return this.isValidVC(vc, signer.did);
        }, this).reduce((result, validity) => {
            return result && validity
        }, true)
    }

    public async isValidVC (vc: JWT, holder?: DID) : Promise<boolean> {
        // verify VC has NOT been tampered
        const verifiedCredential = await verifyCredential(vc, this.resolver);
        if (holder && verifiedCredential.payload.sub !== holder) throw new Error (`Signer is not the subject of VC`);

        // verify the issuer identity is valid
        if (this.isKnownIssuer(verifiedCredential.issuer)) throw new Error (`Unknown Issuer`);
        
        // verify the issuer identity has NOT been revoked
        if (this.isRevoked(verifiedCredential.issuer)) throw new Error (`Deactivated Issuer`);
        
        // verify the VC has NOT been revoked
        const vcID = verifiedCredential.payload.vc.id;
        if (this.isRevoked(vcID)) throw new Error (`Revoked VC`);

        return true;
    }

    public async isRevoked(did : DID) : Promise<boolean> {
        const didDoc = await this.resolver.resolve(did);
        if (didDoc.didDocumentMetadata.deactivated) return true;
        return false;
    }

    public isKnownIssuer(issuer : DID) : boolean {
        for (const key in this.knownIssuer) {
            if (this.knownIssuer[key] === issuer) return true;
        }
        return false;
    }
}