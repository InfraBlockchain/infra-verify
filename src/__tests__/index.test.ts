import Verifier, { VerifierConfig } from '../index';
import { Resolver } from 'did-resolver';
import { getResolver } from 'infra-did-resolver';
import InfraDID from 'infra-did-js'
import { createVerifiableCredentialJwt,
    createVerifiablePresentationJwt,
    Issuer, JwtCredentialPayload } from 'did-jwt-vc'
import {JwtVcIssuer} from 'infra-did-js';

const newIssuer = InfraDID.createPubKeyDIDsecp256k1('01');
const issuers = [
    {
        id: 'kdca',
        did: 'did:infra:01:PUB_K1_5yeJywQqxEjZag6k4C9uXxtMednobVkzgdFxXom9RiEUYR1Hbu',
        privateKey: 'PVT_K1_Y76JJXw39bFPeAM9i5SbkDtjzLxBpQMhktmVUj6x9Y6BUgXKC'
    },
    {
        id: 'moh',
        did: newIssuer.did,
        privateKey: newIssuer.privateKey,
    }
]

const holder = {
    did: 'did:infra:01:PUB_K1_8YQUeS2d9fC3Thq8miSZjFQvzKNjXLpGuMPZN45dy3zu6aSyWt',
    privateKey: 'PVT_K1_pJXb8KBWRFArQRg1nAT57gHHsfguA8NSXWjbauXzN1gRji5kE'
}

const verifier = {
    did: 'did:infra:01:PUB_K1_88APqaXVDMkBv2utSQC54vRpmzyjLe1BweGvLYBgGjTCf1eHVn',
    privateKey: 'PVT_K1_6xS23G7RgdGWsvwSfy8YKLPSHYUddDJC9R5H6xt8kgTTpzVkE'
}

const vcJWT = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJpZCI6ImRpZDppbmZyYTowMTpQVUJfSzFfOFpnYnpRc1NvREd0QWE5M2hEOFdMdEJCWHk2VURuNWtpYzNaZ3FqMzRWQkZadDhYWE0iLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vY29vdi52Yy5pby9wZXJzb25hbCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiUGVyc29uYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6Iuq5gOy_oOu4jCJ9fSwibmJmIjoxNjI0NDY0ODM5LCJpc3MiOiJkaWQ6aW5mcmE6MDE6UFVCX0sxXzZXR3J2bnVHN3hGeENGQTRkUHJlZmg5M0hVZEc3ZDFmalVRTnNaWFE2SmZSQzZHM1pDIn0.XVXpj9MPm6lBUu1tDLHeDvWEfXU9vw79UWcvlocWZpuiaF774gNXpMPwsAExsGcaWaQvASUbjxm18meP22LqDQ'
const validVcJwt = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6ImRpZDppbmZyYTowMTpQVUJfSzFfNkE1YnBMQjlqd2RHWkdhMXU0V2RwclBmUjVXTFBtZWkzbXl1QUd5QldBZGFHWHNlNlYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmFjY2luYXRpb24iXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6aW5mcmE6MDE6UFVCX0sxXzhZUVVlUzJkOWZDM1RocThtaVNaakZRdnpLTmpYTHBHdU1QWk40NWR5M3p1NmFTeVd0IiwibmFtZSI6Iuq5gOy_oOu4jCJ9fSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84WVFVZVMyZDlmQzNUaHE4bWlTWmpGUXZ6S05qWExwR3VNUFpONDVkeTN6dTZhU3lXdCIsIm5iZiI6MTYyNTAyNjcwNSwiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV81eWVKeXdRcXhFalphZzZrNEM5dVh4dE1lZG5vYlZremdkRnhYb205UmlFVVlSMUhidSJ9.ynNYeOiy-H1th0CBl35eWKl5MdmRz5XuWe8dO6RqYkAEAetg9Zhb9k7BBktuTtegezfh9WgEQwJy3V_bRdgRPA'
const unknownIssuerVcJWT = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJpZCI6ImRpZDppbmZyYTowMTpQVUJfSzFfOFpnYnpRc1NvREd0QWE5M2hEOFdMdEJCWHk2VURuNWtpYzNaZ3FqMzRWQkZadDhYWE0iLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vY29vdi52Yy5pby9wZXJzb25hbCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiUGVyc29uYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6Iuq5gOy_oOu4jCJ9fSwibmJmIjoxNjI0NDY0ODM5LCJpc3MiOiJkaWQ6aW5mcmE6MDE6UFVCX0sxXzZXR3J2bnVHN3hGeENGQTRkUHJlZmg5M0hVZEc3ZDFmalVRTnNaWFE2SmZSQzZHM1pDIn0.XVXpj9MPm6lBUu1tDLHeDvWEfXU9vw79UWcvlocWZpuiaF774gNXpMPwsAExsGcaWaQvASUbjxm18meP22LqDQ'
const invalidVc = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ2ZXJzaW9uIjoiMDAxIiwiZXhwIjoxNjIzMDQyMzk3LCJzdWIiOiI2YTRjODQyMjdiODQ0NmNiOGQwMjZhMjBlZDM0MjY5MSIsImlzcyI6Ik5BVkVSIn0.8uMLo8yR8MuBZvm30AUEi7By67LbnifvqevoGMJ8j4g'
const revokedIDVcJwt = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6ImRpZDppbmZyYTowMTpQVUJfSzFfNU12YWRUSzhLN2M4aFJXMUJDNVgzZ0puNmJ0SjU5TEFvaXlYZWp6QWFlaDRUY2lTcTUiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmFjY2luYXRpb24iXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6aW5mcmE6MDE6UFVCX0sxXzhZUVVlUzJkOWZDM1RocThtaVNaakZRdnpLTmpYTHBHdU1QWk40NWR5M3p1NmFTeVd0IiwibmFtZSI6Iuq5gOy_oOu4jCJ9fSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84WVFVZVMyZDlmQzNUaHE4bWlTWmpGUXZ6S05qWExwR3VNUFpONDVkeTN6dTZhU3lXdCIsIm5iZiI6MTYyNTAyMzUxNiwiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV81eWVKeXdRcXhFalphZzZrNEM5dVh4dE1lZG5vYlZremdkRnhYb205UmlFVVlSMUhidSJ9.u9YNhHXHudk7asvhJm1TygPxwADy5vI_7tpFGZdgEJqoMXGyfQ1WgztVIqex2Pi0Inw5MykR-0Ez1O_bumTe3A'
const vpJWT = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjIyMjQ1MjE2MTksInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZVekkxTmtzaUxDSjBlWEFpT2lKS1YxUWlmUS5leUoyWXlJNmV5SnBaQ0k2SW1ScFpEcHBibVp5WVRvd01UcFFWVUpmU3pGZk9GcG5ZbnBSYzFOdlJFZDBRV0U1TTJoRU9GZE1kRUpDV0hrMlZVUnVOV3RwWXpOYVozRnFNelJXUWtaYWREaFlXRTBpTENKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3ZNakF4T0M5amNtVmtaVzUwYVdGc2N5OTJNU0lzSW1oMGRIQnpPaTh2WTI5dmRpNTJZeTVwYnk5d1pYSnpiMjVoYkNKZExDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpVUdWeWMyOXVZV3dpWFN3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2libUZ0WlNJNkl1cTVnT3lfb091NGpDSjlmU3dpYm1KbUlqb3hOakkwTkRZME9ETTVMQ0pwYzNNaU9pSmthV1E2YVc1bWNtRTZNREU2VUZWQ1gwc3hYelpYUjNKMmJuVkhOM2hHZUVOR1FUUmtVSEpsWm1nNU0waFZaRWMzWkRGbWFsVlJUbk5hV0ZFMlNtWlNRelpITTFwREluMC5YVlhwajlNUG02bEJVdTF0RExIZUR2V0VmWFU5dnc3OVVXY3Zsb2NXWnB1aWFGNzc0Z05YcE1Qd3NBRXhzR2NhV2FRdkFTVWJqeG0xOG1lUDIyTHFEUSJdfSwibmJmIjoxNjI0NTIxNjE5LCJpc3MiOiJkaWQ6aW5mcmE6MDE6UFVCX0sxXzhZUVVlUzJkOWZDM1RocThtaVNaakZRdnpLTmpYTHBHdU1QWk40NWR5M3p1NmFTeVd0IiwiYXVkIjpbImRpZDppbmZyYTowMTpQVUJfSzFfODhBUHFhWFZETWtCdjJ1dFNRQzU0dlJwbXp5akxlMUJ3ZUd2TFlCZ0dqVENmMWVIVm4iXSwibm9uY2UiOiJkaWQ6aW5mcmE6MDE6UFVCX0sxXzVhcTF6Z0pWdVRzdEhWSnJTRVA5MzZqNXJGNkRQUVZtUWp1TUg2TTNYREV2eXFIY25mIn0.GvQLXqlMH-Lbh8_W890JuDCBnKAzDks2Ls-6taagO5W2X4OaFRHh8fMup23NRQ7Te_gXAiRIldlPKW0OjC0jiA'

const revokedDID = [
    {
        did: 'did:infra:01:PUB_K1_5MvadTK8K7c8hRW1BC5X3gJn6btJ59LAoiyXejzAaeh4TciSq5',
        privateKey: 'PVT_K1_JvgScaemkSoKCmtc7BiDoiGMrtjFkW7RX79vXQ3mQPaepVjHE'
    }
]

const config : VerifierConfig = {
    networkConfig: {
        networks: [
            {
                networkId: '01',
                registryContract: 'infradidregi',
                rpcEndpoint: 'http://kdca.osong.bc.coov.io:9180/'
            },
            {
                networkId : '01',
                registryContract : 'fmapkumrotfc',
                rpcEndpoint : 'https://api.testnet.eos.io'
            },
        ],
    },
    did: verifier.did,
    knownIssuers: issuers
}

describe('Initialize Verifier', () => {
    let verifier : Verifier;
    it('initialize without resolver', () => {
        verifier = new Verifier(config);
        expect(verifier).toBeDefined();
    })

    it('and see if it works', async () => {
        const doc = await verifier.resolver.resolve(holder.did);
        // console.log(doc);
        expect(doc.didDocument?.id).toBe(holder.did);
    })

    beforeAll(async () => {
        config.resolver = new Resolver(getResolver(config.networkConfig));
    })

    it('initialize with resolver', () => {
        const verifier = new Verifier(config);
        expect(verifier).toBeDefined();
    })

    it('and see if it works', async () => {
        const doc = await verifier.resolver.resolve(holder.did);
        expect(doc.didDocument?.id).toBe(holder.did);
    })

    it('initialize with did', () => {
        const verifier = new Verifier({...config, did: holder.did});
        expect(verifier.did).toBe(holder.did);
    })

    it('initialize with knownIssuer', () => {
        const verifier = new Verifier({...config, knownIssuers: issuers});
        expect(verifier.knownIssuers[0].id).toBe('kdca');
        expect(verifier.knownIssuers[0].did).toBe('did:infra:01:PUB_K1_5yeJywQqxEjZag6k4C9uXxtMednobVkzgdFxXom9RiEUYR1Hbu');
    })

    describe('function ready()', () => {
        const verifier = new Verifier(config);
        const { challenge, aud } = verifier.ready();
        it('challenge is not null', () => {
            expect(challenge).toBeDefined();
        })
        it('challenge is set to verifier', () => {
            expect(challenge).toBe(verifier.challenge);
        })
        it('challenge must be strong enough', () => {
            expect(challenge.length).toBeGreaterThan(20);
        })
        it('aud is not null', () => {
            expect(aud).toBeDefined();
        })
        it("aud is verifier's DID", () => {
            expect(aud).toBe(verifier.did);
        })
    })
})

describe('Test Verify', () => {
    const verifier = new Verifier(config);
    it('function getVPClaims', () => {
        expect(verifier.getVPClaims(vpJWT)).toEqual({
            "name": "김쿠브"
        })
    })

    it('function getVCClaims', () => {
        expect(verifier.getVCClaims(unknownIssuerVcJWT)).toEqual({
        "name": "김쿠브"
        })
    })

    it('function getVCClaims', () => {
        expect(verifier.getVCClaims(vcJWT)).toEqual({
            "name": "김쿠브"
        })
    })

    it('function getVCClaims', () => {
        expect(verifier.getVCClaims(unknownIssuerVcJWT)).not.toEqual({
            "claim": "something else"
        })
    })

    describe("is Valid Function", () => {
        const confDefaults =  {
            networkId: '01',
            registryContract: 'infradidregi',
            rpcEndpoint: 'http://kdca.osong.bc.coov.io:9180/'
        };

        it("Valid check VC - Unsupported type", async () => {
            try {
                await verifier.isValid(invalidVc)
            } catch (err) {
                expect(err.message).toEqual(`Unsupported type`)
            }
        })

        it("Valid check VC", async () => {
            await expect(verifier.isValid(validVcJwt)).resolves.toBeTruthy();
        })

        it("Valid check VC - Unknown Issuer", async () => {
            try {
                await verifier.isValid(unknownIssuerVcJWT)
            } catch (err) {
                expect(err.message).toEqual(`Unknown Issuer`)
            }
        })

        it("Valid check VC - Signer is not the subject of VC", async () => {
            const vcIssuerConf = {
                ...confDefaults,
                did : issuers[0].did,
                didOwnerPrivateKey : issuers[0].privateKey||"string"
            }

            const issuerApi = new InfraDID(vcIssuerConf);
            const createdVc = await createVcJwt(holder.did, issuerApi.getJwtVcIssuer());
            try {
                await verifier.isValidVC(createdVc, issuers[0].did);
            } catch (err) {
                expect(err.message).toEqual(`Signer is not the subject of VC`)
            }
        })

        it("Valid check VC - Revoked VC", async () => {
            try {
                await verifier.isValid(revokedIDVcJwt)
            } catch (err) {
                expect(err.message).toEqual(`Revoked VC`)
            }
        })

        it("Valid check VC - Deactivated Issuer", async () => {
            const vcIssuerConf = {
                ...confDefaults,
                did : revokedDID[0].did,
                didOwnerPrivateKey : revokedDID[0].privateKey||"string"
            }

            issuers.push({id : 'revoked Issuer',
                did : vcIssuerConf.did,
                privateKey: vcIssuerConf.didOwnerPrivateKey})

            const issuerApi = new InfraDID(vcIssuerConf);
            const createdVc = await createVcJwt(holder.did, issuerApi.getJwtVcIssuer());
            try {
                await verifier.isValid(createdVc);
            } catch (err) {
                expect(err.message).toEqual(`Deactivated Issuer`)
            }
        })

        it("Valid check VP - Deactivated Presenter", async () => {
            const vpIssuerConf = {
                ...confDefaults,
                did : revokedDID[0].did,
                didOwnerPrivateKey : revokedDID[0].privateKey||"string"
            }

            const vpIssuerApi = new InfraDID(vpIssuerConf);
            const createdVp = await createVpJwt(unknownIssuerVcJWT, vpIssuerApi.getJwtVcIssuer())
            try {
                await verifier.isValid(createdVp)
            } catch (err) {
                expect(err.message).toEqual(`Deactivated Presenter`);
            }
        })

        it("Valid check VP", async () => {
            const vpIssuerConf = {
                ...confDefaults,
                did : holder.did,
                didOwnerPrivateKey : holder.privateKey||"string"
            }

            const vpIssuerApi = new InfraDID(vpIssuerConf);

            const createdVp = await createVpJwt(validVcJwt, vpIssuerApi.getJwtVcIssuer())
            await expect(verifier.isValid(createdVp)).resolves.toBeTruthy();
        })
    })
})

const createVcJwt = async (did : string, vcIssuerDID : JwtVcIssuer) => {
    const vcPayload: JwtCredentialPayload = {
        sub: did,
        nbf: Math.floor(Date.now() / 1000),
        vc: {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            id: InfraDID.createPubKeyDIDsecp256k1('01').did,
            type: ["VerifiableCredential", "Vaccination"],
            credentialSubject: {
                id: did,
                "name": "김쿠브"
            },
        },
    };
    return await createVerifiableCredentialJwt(vcPayload, vcIssuerDID);
};

const createVpJwt = async (vcJwt : string, holder : Issuer) => {
    const presentation = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: 'VerifiablePresentation',
        verifiableCredential: [vcJwt],
        holder: holder.did,
        verifier: verifier.did,
        issuanceDate: new Date().toISOString(),
        expirationDate: new Date(new Date().getTime() + 600000 * 1000).toISOString(),
    }
    const challenge = InfraDID.createPubKeyDIDsecp256k1('01').did;
    return await createVerifiablePresentationJwt(presentation, holder, {challenge : challenge, domain : verifier.did})
};