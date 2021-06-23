import Verifier, { VerifierConfig } from '../index';
import { Resolver } from 'did-resolver';
import { getResolver } from 'infra-did-resolver';
import InfraDID from 'infra-did-js'
import { ConfigurationOptions } from 'infra-did-resolver';
import exp from 'constants'
import { decodeJWT } from 'did-jwt'
import { createVerifiableCredentialJwt,
    verifyCredential,
    createVerifiablePresentationJwt,
    verifyPresentation,
    CredentialPayload,
    PresentationPayload,
    VerifiableCredential } from 'did-jwt-vc'

const issuers = [
    {
        id: 'kdca',
        did: 'did:infra:01:PUB_K1_5yeJywQqxEjZag6k4C9uXxtMednobVkzgdFxXom9RiEUYR1Hbu',
        privateKey: 'PVT_K1_Y76JJXw39bFPeAM9i5SbkDtjzLxBpQMhktmVUj6x9Y6BUgXKC'
    },
    {
        id: 'moh',
        did: 'did:infra:01:PUB_K1_6WGrvnuG7xFxCFA4dPrefh93HUdG7d1fjUQNsZXQ6JfRC6G3ZC',
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

//decoded vcJWT payload
/*
{
  "vc": {
    "id": "did:infra:01:PUB_K1_8ZgbzQsSoDGtAa93hD8WLtBBXy6UDn5kic3Zgqj34VBFZt8XXM",
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://coov.vc.io/personal"
    ],
    "type": [
      "VerifiableCredential",
      "Personal"
    ],
    "credentialSubject": {
      "name": "김쿠브"
    }
  },
  "nbf": 1624464839,
  "iss": "did:infra:01:PUB_K1_6WGrvnuG7xFxCFA4dPrefh93HUdG7d1fjUQNsZXQ6JfRC6G3ZC"
}
 */

const vpJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJleHAiOjE2MjM5MDM2NzEsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc2lmUS5leUoyWXlJNmV5SmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpqYkdGcGJURWlPaUpqYkdGcGJURmZkbUZzZFdVaUxDSmpiR0ZwYlRJaU9pSmpiR0ZwYlRKZmRtRnNkV1VpZlN3aVFHTnZiblJsZUhRaU9sc2lhSFIwY0hNNkx5OTNkM2N1ZHpNdWIzSm5Mekl3TVRndlkzSmxaR1Z1ZEdsaGJITXZkakVpWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbFpoWTJOcGJtRjBhVzl1UTNKbFpHVnVkR2xoYkNKZGZTd2ljM1ZpSWpvaVpHbGtPbWx1Wm5KaE9qQXhPbEJWUWw5TE1WODNha05FWVhKWWJsb3pVMlJRUVhkbVJrVmphVlJUZVZWNlFUUm1ibVp1YTNSMlJrZzVSbW8zU2pnNVZYSkdhVWh3ZENJc0ltcDBhU0k2SW1oMGRIQTZMeTlsZUdGdGNHeGxMblpqTDJOeVpXUmxiblJwWVd4ekx6RXlNelV6TWlJc0ltNWlaaUk2TVRZeE5UazROekV4Tnl3aWFYTnpJam9pWkdsa09tbHVabkpoT2pBeE9sQlZRbDlMTVY4NFVIZEhOMjltTlVJNGNEbE5jR0YzTmxoNlpYbFpkRk5YU25sbFUxaFdkSGhhYUZCSVVVTTFaVnA0V2tOcmNXbE1WU0o5LnRHU0FzRWJGNGJLYjViRVdOdFUxbkl0YU1UWXJhU3N0YUQyY3hTZms5SzEzS1pET1UwN08zYzYtMnU5UUtXcHhIQW0wWmhER3E5UVEwN1hEZUdvcW13Il19LCJuYmYiOjE2MjM5MDMwNzEsImlzcyI6ImRpZDppbmZyYTowMTpQVUJfSzFfN2pDRGFyWG5aM1NkUEF3ZkZFY2lUU3lVekE0Zm5mbmt0dkZIOUZqN0o4OVVyRmlIcHQiLCJhdWQiOlsiZGlkOmluZnJhOjAxOlBVQl9LMV81VGFFZ3BWdXIzOTFkaW1WbkZDREhCMTIyRFhZQmJ3V2RLVXBFSkNOdjNrbzFLTVl3eiJdLCJub25jZSI6ImRpZDppbmZyYTowMTpQVUJfSzFfN2tGOVFheTlWMmRSblhKUXk0dHo2WVRtYjFtZFlEY2hYdnNRdFFObmFYUmNhVlZ1TGEifQ.0N8Tpw6DZZZqpe5FkUHVxIm5eBKWEjTsfra0Urg7gLhJ7-0c_SfV2D5c2orT-73eyfuB2HcDuCYRf3yvZPoNcw';
/*
{
  "exp": 1623903671,
  "vp": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
      "VerifiablePresentation"
    ],
    "verifiableCredential": [
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYxNTk4NzExNywiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.tGSAsEbF4bKb5bEWNtU1nItaMTYraSstaD2cxSfk9K13KZDOU07O3c6-2u9QKWpxHAm0ZhDGq9QQ07XDeGoqmw"
    ]
  },
  "nbf": 1623903071,
  "iss": "did:infra:01:PUB_K1_7jCDarXnZ3SdPAwfFEciTSyUzA4fnfnktvFH9Fj7J89UrFiHpt",
  "aud": [
    "did:infra:01:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz"
  ],
  "nonce": "did:infra:01:PUB_K1_7kF9Qay9V2dRnXJQy4tz6YTmb1mdYDchXvsQtQNnaXRcaVVuLa"
}
 */

const config = {
    networkConfig: {
        networks: [
            {
                networkId: '01',
                registryContract: 'infradidregi',
                rpcEndpoint: 'http://kdca.osong.bc.coov.io:9180/'
            },
        ],
    },
    did: verifier.did,
    knownIssuers: issuers,
}

describe('Initialize Verifier', () => {
    let verifier
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
        expect(verifier.getVPClaims(vpJWT)).toBe({"claim1": "claim1_value","claim2":"claim2_value"})
    })

    it('function getVCClaims', () => {
        expect(verifier.getVCClaims(vcJWT)).toBe({
            //"id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
            "name": "김쿠브"
        })
    })

    it('function getVCClaims', () => {
        expect(verifier.getVCClaims(vcJWT)).not.toBe({
            //"id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
            "claim": "something else"
        })
    })

    // it('verifies vcJWT', async () => {
    //     const result = await verifier.isValid(vcJWT);
    //     expect(result).toBeTruthy();
    // })

    // it('function isValid', async () => {
    //     const invalidJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTS1RQQVNTIiwic3ViIjoiZDA2ODNmNTI0ZTk3Njc2M2VmMzViMTRhMmMzYzA2YWIiLCJleHAiOjE2MjMwNDI4ODMsInZlcnNpb24iOiIwMDIifQ.AjCMbXFZVQkFfW3aUs_BphWvnVu-CNAWaE-dHNYFt6w';
    //     expect(await verifier.isValid(vcJWT)).toBeTruthy();
    //     await expect(verifier.isValid(vpJWT)).toBeTruthy();
    //     await expect(verifier.isValid(invalidJWT)).rejects.toThrowError(`Unsupported type`)
    // })

    // it('function isKnownIssuer',() => {
    //     expect(verifier.isKnownIssuer(config.knownIssuers[0].did)).toBeTruthy();
    //     expect(verifier.isKnownIssuer(`did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr`)).toBeFalsy()
    // })

    // it('function isRevoked',() => {
    //   expect(verifier.isRevoked(verifier.did)).toBeTruthy();

    //   const networkId = '01'
    //   const registryContract = 'fmapkumrotfc'
    //   const rpcEndpoint = 'https://api.testnet.eos.io'
    //   const txfeePayerAccount = 'qwexfhmvvdci'
    //   const txfeePayerPrivateKey = '5KV84hXSJvu3nfqb9b1raRMnzvULaHH6Fsaz4xBZG2QbfPwMg76' // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db

    //   const confDefaults = {
    //     networkId,
    //     registryContract,
    //     rpcEndpoint,
    //     txfeePayerAccount,
    //     txfeePayerPrivateKey,
    //   }
    //   const conf = {
    //     ...confDefaults,
    //     did: `did:infra:${networkId}:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`,
    //     didOwnerPrivateKey: 'PVT_K1_2QUHdXAKxtfbCbFDL5FoVtLpPp6sWQpXzRpW7dXXZFS2qVqFFn'
    //   }

    //   const didApi = new InfraDID(conf);
    //   didApi.revokePubKeyDID();

    //   expect(verifier.isRevoked(conf.did)).rejects.toBeFalsy();
    // })

    describe("is Valid Function", () => {
        const conf = {
            networkId: '01',
            registryContract: 'fmapkumrotfc',
            rpcEndpoint: 'https://api.testnet.eos.io',
            txfeePayerAccount: 'qwexfhmvvdci',
            txfeePayerPrivateKey: '5KV84hXSJvu3nfqb9b1raRMnzvULaHH6Fsaz4xBZG2QbfPwMg76', // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db,
            did: `did:infra:01:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`,
            didOwnerPrivateKey: 'PVT_K1_2QUHdXAKxtfbCbFDL5FoVtLpPp6sWQpXzRpW7dXXZFS2qVqFFn'
        }
        
        it("Successfully making valid VC", async () => {
            // const holder = "did:infra:01:PUB_K1_7kF9Qay9V2dRnXJQy4tz6YTmb1mdYDchXvsQtQNnaXRcaVVuLa"

            // const newIssuer = InfraDID.createPubKeyDIDsecp256k1('01');
            // verifier.knownIssuers.push({id:'new Issuer', did: newIssuer.did })

            // const issuerAPI = new InfraDID({
            //     ...conf,
            //     did: newIssuer.did,
            //     didOwnerPrivateKey: newIssuer.privateKey,
            // });
            // const issuer = await issuerAPI.getJwtVcIssuer()

            // const payload: CredentialPayload = {
            //     '@context': ['https://www.w3.org/2018/credentials/v1'],
            //     id: 'http://example.vc/credentials/123532',
            //     type: ['VerifiableCredential', 'VaccinationCredential'],
            //     // issuanceDate: '2021-03-17T12:17:26.000Z',
            //     issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
            //     credentialSubject: {
            //         id: "did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr",
            //         claim1: 'claim1_value',
            //         claim2: 'claim2_value'
            //     }
            // }
            // const createdVC = await createVerifiableCredentialJwt(payload, issuer);
            await verifier.isValidVC(vcJWT)
        })

        // it("Error : Unknown Issuer", async () => {
        //     const issuerApi = new InfraDID(conf);
        //     const issuer = issuerApi.getJwtVcIssuer()

        //     const credential = {
        //         '@context': ['https://www.w3.org/2018/credentials/v1'],
        //         id: 'http://example.vc/credentials/123532',
        //         type: ['VerifiableCredential', 'VaccinationCredential'],
        //         issuer: conf.did,
        //         // issuanceDate: '2021-03-17T12:17:26.000Z',
        //         issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
        //         credentialSubject: {
        //             id: "did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr",
        //             claim1: 'claim1_value',
        //             claim2: 'claim2_value'
        //         }
        //     }
        //     const createdJWTvc = await createVerifiableCredentialJwt(credential,issuer);
        //     console.log(decodeJWT(createdJWTvc))
        //     try {
        //         await verifier.isValidVC(createdJWTvc)
        //     } catch (err) {
        //         expect(err.message).toBe(`Unknown Issuer`)
        //     }
        // })
        // test("Error : Deactivated Issuer", async () => {
        //     const issuerDID = InfraDID.createPubKeyDIDsecp256k1('01');
        //     verifier.knownIssuers.push({id:'will revoke', did:issuerDID.did})

        //     const issuerConf = {
        //         ...confDefaults,
        //         did: issuerDID.did,
        //         didOwnerPrivateKey: issuerDID.privateKey
        //     }

        //     console.log(verifier.knownIssuers)

        //     const issuerApi = new InfraDID(issuerConf);
        //     const issuer = issuerApi.getJwtVcIssuer()

        //     const credential = {
        //         '@context': ['https://www.w3.org/2018/credentials/v1'],
        //         id: 'http://example.vc/credentials/123532',
        //         type: ['VerifiableCredential', 'VaccinationCredential'],
        //         issuer: issuerDID.did,
        //         // issuanceDate: '2021-03-17T12:17:26.000Z',
        //         issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
        //         credentialSubject: {
        //             id: "did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr",
        //             claim1: 'claim1_value',
        //             claim2: 'claim2_value'
        //         }
        //     }
        //     const createdJWTvc = await createVerifiableCredentialJwt(credential,issuer);
        //     issuerApi.revokePubKeyDID()
        //     console.log(decodeJWT(createdJWTvc))
        //     try {
        //         await verifier.isValidVC(createdJWTvc)
        //     } catch (err) {
        //         expect(err.message).toBe(`Deactivated Issuer`);
        //     }
        // })
        // it("Error : Revoked VC", async () => {
        //     const issuerDID = InfraDID.createPubKeyDIDsecp256k1('01');
        //     verifier.knownIssuers.push({id:'Added Issuer', did:issuerDID.did})

        //     const issuerApi = new InfraDID(conf);
        //     const issuer = issuerApi.getJwtVcIssuer()

        //     const vcID_conf = {
        //         ...confDefaults,
        //         did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`, //pubKeyDID.did,
        //         didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', //pubKeyDID.privateKey,
        //     }
        //     const vcID_api = new InfraDID(vcID_conf);

        //     const credential = {
        //         '@context': ['https://www.w3.org/2018/credentials/v1'],
        //         id: 'http://example.vc/credentials/123532',
        //         type: ['VerifiableCredential', 'VaccinationCredential'],
        //         issuer: conf.did,
        //         // issuanceDate: '2021-03-17T12:17:26.000Z',
        //         issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
        //         credentialSubject: {
        //             id: vcID_conf.did,
        //             claim1: 'claim1_value',
        //             claim2: 'claim2_value'
        //         }
        //     }

        //     const createdJWTvc = await createVerifiableCredentialJwt(credential,issuer);
        //     vcID_api.revokePubKeyDID()
        //     console.log(decodeJWT(createdJWTvc))
        //     try {
        //         await verifier.isValidVC(createdJWTvc);
        //     } catch (err) {
        //         expect(err.message).toBe(`Revoked VC`);
        //     }
        // })
        // it("Return True", async () => {

        // })
    } )

    // it('function isValidVP', async () => {
    //     expect(await verifier.isValidVP(vpJWT)).toBeFalsy();
    // })
})
