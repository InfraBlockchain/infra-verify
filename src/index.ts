import { decodeJWT } from 'did-jwt';
import { verifyPresentation, verifyCredential, VerifiablePresentation, VerifiableCredential } from 'did-jwt-vc';
import { Resolver, Resolvable, DIDResolutionResult } from 'did-resolver';
import { getResolver, ConfigurationOptions } from 'infra-did-resolver';
import InfraDID from 'infra-did-js';

export interface VerifierConfig {
    resolver?: Resolvable
    networkConfig: ConfigurationOptions
    did: string
    knownIssuers: Issuer[]
}

export type JWT = string
export type DID = string
export type Issuer = {
    id: string,
    did: DID
}

export default class Verifier {
    public resolver: Resolvable
    public challenge: string
    public did: string
    public knownIssuers: Issuer[]

    constructor (config : VerifierConfig) {
        this.resolver = config.resolver ? config.resolver : new Resolver(getResolver(config.networkConfig));
        this.did = config.did ? config.did : InfraDID.createPubKeyDIDsecp256k1('01').did;
        this.challenge = '';
        this.knownIssuers = config.knownIssuers;
    }

    public ready() : { challenge: string, aud: string } {
        this.challenge = this.generateChallenge();
        return { challenge: this.challenge, aud: this.did };
    }

    private generateChallenge() : string {
        // use randomly generated DID as nonce for now
        return InfraDID.createPubKeyDIDsecp256k1('01').did;
    }

    public getVPClaims(vp: JWT) : any {
        const vcList = decodeJWT(vp).payload.vp.verifiableCredential;
        return vcList.map((vc : JWT) => {
            return this.getVCClaims(vc);
        }).reduce((result : any, claims : any) => {
            return { ...claims, ...result }
        }, {});
    }

    public getVCClaims(vc: JWT) : any {
        return decodeJWT(vc).payload.vc.credentialSubject;
    }

    public async isValid(jwt: JWT) : Promise<boolean> {
        const decoded = decodeJWT(jwt);
        if (decoded.payload.vp) return this.isValidVP(jwt);
        else if (decoded.payload.vc) return this.isValidVC(jwt);
        else throw new Error (`Unsupported type`);
    }

    public async isValidVP (vp: JWT) : Promise<boolean> {
        // verify VP has been issued to the verifier with correct challenge
        const verifiedPresentation = await verifyPresentation(vp, this.resolver, { challenge: this.challenge, audience: this.did })
<<<<<<< HEAD
        const vcList = verifiedPresentation.payload.vp.verifiableCredential;
        const signer  = verifiedPresentation.payload.iss;
        if (signer && await this.isRevoked(signer)) throw new Error (`Deactivated Presenter`);
        return vcList.map((vc : JWT) => {
            return this.isValidVC(vc, signer);
=======
        //const vcList = verifiedPresentation.payload.vp.VerifiedCredential;
        // const signer = verifiedPresentation.payload.signer;
        const vcList = verifiedPresentation.payload.vp.verifiableCredential;
        const signer = verifiedPresentation.signer

        //if (this.isRevoked(signer.did)) throw new Error (`Deactivated Presenter`);
        //await를 안쓰면, pending이 나와서 true로 리턴됨, signer.id는 verifiedPresentation.signer에 있음
        if (await this.isRevoked(signer.id)) throw new Error (`Deactivated Presenter`);
        return vcList.map((vc : JWT) => {
            //return this.isValidVC(vc, signer.did);
            return this.isValidVC(vc, signer.id);
>>>>>>> 08153e94985b5e257751839f2dea7529247d7ec1
        }, this).reduce((result : boolean, validity : boolean) => {
            return result && validity
        }, true)
    }

    public async isValidVC (vc: JWT, holder?: DID) : Promise<boolean> {
        // verify VC has NOT been tampered
        const verifiedCredential = await verifyCredential(vc, this.resolver);
        if (holder && verifiedCredential.payload.sub !== holder) throw new Error (`Signer is not the subject of VC`);
        // verify the issuer identity is valid
        if (!this.isKnownIssuer(verifiedCredential.issuer)) throw new Error (`Unknown Issuer`);
        // verify the issuer identity has NOT been revoked
<<<<<<< HEAD
        if (await this.isRevoked(verifiedCredential.issuer)) throw new Error (`Deactivated Issuer`);
        // verify the VC has NOT been revoked
        const vcID = verifiedCredential.payload.vc.id;
=======
        //if (this.isRevoked(verifiedCredential.issuer)) throw new Error (`Deactivated Issuer`);
        if (await this.isRevoked(verifiedCredential.issuer)) throw new Error (`Deactivated Issuer`);
        // verify the VC has NOT been revoked
        const vcID = verifiedCredential.payload.vc.id;
        //if (this.isRevoked(vcID)) throw new Error (`Revoked VC`);
>>>>>>> 08153e94985b5e257751839f2dea7529247d7ec1
        if (await this.isRevoked(vcID)) throw new Error (`Revoked VC`);
        return true;
    }

    public async isRevoked(did : DID) : Promise<boolean> {
        const didDoc : DIDResolutionResult = await this.resolver.resolve(did);
        if (didDoc.didDocumentMetadata.deactivated) return true;
        return false;
    }

    public isKnownIssuer(issuer : DID) : boolean {
        const found = this.knownIssuers.some(known => known.did === issuer)
        if (!found) return false
        return true
    }
}