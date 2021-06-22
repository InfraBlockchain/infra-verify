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

const testDID = 'did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn';
const testIssuers = [
    { id: "kdca", did : 'did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn'},
    { id: "moh", did : 'did:infra:01:PUB_K1_6bHihw3zP9VR1ezxZGay3wsoQxKQuzyCzkw9TJcWMHUtvLYtpJ'}]

const vcJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJjcmVkZW50aWFsU3ViamVjdCI6eyJjbGFpbTEiOiJjbGFpbTFfdmFsdWUiLCJjbGFpbTIiOiJjbGFpbTJfdmFsdWUifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZhY2NpbmF0aW9uQ3JlZGVudGlhbCJdfSwic3ViIjoiZGlkOmluZnJhOjAxOlBVQl9LMV83akNEYXJYblozU2RQQXdmRkVjaVRTeVV6QTRmbmZua3R2Rkg5Rmo3Sjg5VXJGaUhwdCIsImp0aSI6Imh0dHA6Ly9leGFtcGxlLnZjL2NyZWRlbnRpYWxzLzEyMzUzMiIsIm5iZiI6MTYyNDI1MjA4NSwiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.5NZLwoyoS6XDmug4AanzJ7dXyMrnfMQ1435f4G3EB3WLjVDwI9C6DyI3MQhIh89atmMa_g3h9gLavqSRADD_0g'

//decoded vcJWT payload
/*
{
  "iat": 1623902576,
  "aud": "did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr",
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
      "VerifiableCredential"
    ],
    "credentialSubject": {
      "id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
      "claim1": "claim1_value",
      "claim2": "claim2_value"
    }
  },
  "iss": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU"
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

describe('Initialize Verifier', () => {
    const config: VerifierConfig = {
        networkConfig: {
            networks: [
                {
                    networkId: '01',
                    registryContract: 'infradidregi',
                    rpcEndpoint: 'http://kdca.osong.bc.coov.io:9180/'
                },
            ],
        },
        did: '',
        knownIssuers: [],
    }
    let verifier : Verifier;
    it('initialize without resolver', () => {
        verifier = new Verifier(config);
        expect(verifier).toBeDefined();
    })

    it('and see if it works', async () => {
        const doc = await verifier.resolver.resolve(testDID);
        // console.log(doc);
        expect(doc.didDocument?.id).toBe(testDID);
    })

    beforeAll(async () => {
        config.resolver = new Resolver(getResolver(config.networkConfig));
    })

    it('initialize with resolver', () => {
        const verifier = new Verifier(config);
        expect(verifier).toBeDefined();
    })

    it('and see if it works', async () => {
        const doc = await verifier.resolver.resolve(testDID);
        expect(doc.didDocument?.id).toBe(testDID);
    })

    it('initialize with did', () => {
        const verifier = new Verifier({...config, did: testDID});
        expect(verifier.did).toBe(testDID);
    })

    it('initialize with knownIssuer', () => {
        const verifier = new Verifier({...config, knownIssuers: testIssuers});
        expect(verifier.knownIssuers[0].id).toBe('kdca');
        expect(verifier.knownIssuers[0].did).toBe('did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn');
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

describe('Get Verify', () => {
    const config: VerifierConfig = {
        networkConfig: {
            networks: [
                {
                    networkId: '01',
                    registryContract: 'infradidregi',
                    rpcEndpoint: 'http://kdca.osong.bc.coov.io:9180/'
                },
            ],
        },
        did: 'did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn',
        knownIssuers: [
            { id: "kdca", did : 'did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn'},
            { id: "moh", did : 'did:infra:01:PUB_K1_6bHihw3zP9VR1ezxZGay3wsoQxKQuzyCzkw9TJcWMHUtvLYtpJ'}]
    }
    config.resolver = new Resolver(getResolver(config.networkConfig));

    const verifier = new Verifier(config);

    it('function getVPClaims', () => {
        expect(verifier.getVPClaims(vpJWT)).toEqual({"claim1": "claim1_value","claim2":"claim2_value"})
    })

    it('function getVCClaims', () => {
        expect(verifier.getVCClaims(vcJWT)).toEqual({
            //"id": "did:infra:01:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU",
            "claim1": "claim1_value",
            "claim2": "claim2_value"
        })
    })

    it('function isValid', async () => {
        const invalidJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTS1RQQVNTIiwic3ViIjoiZDA2ODNmNTI0ZTk3Njc2M2VmMzViMTRhMmMzYzA2YWIiLCJleHAiOjE2MjMwNDI4ODMsInZlcnNpb24iOiIwMDIifQ.AjCMbXFZVQkFfW3aUs_BphWvnVu-CNAWaE-dHNYFt6w';
        await expect(verifier.isValid(vcJWT)).toBeTruthy();
        await expect(verifier.isValid(vpJWT)).toBeTruthy();
        await expect(verifier.isValid(invalidJWT)).rejects.toThrowError(`Unsupported type`)
    })

    it('function isKnownIssuer',() => {
        expect(verifier.isKnownIssuer(config.knownIssuers[0].did)).toBeTruthy();
        expect(verifier.isKnownIssuer(`did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr`)).toBeFalsy()
    })

    it('function isRevoked',() => {
      expect(verifier.isRevoked(verifier.did)).toBeTruthy();

      const networkId = '01'
      const registryContract = 'fmapkumrotfc'
      const rpcEndpoint = 'https://api.testnet.eos.io'
      const txfeePayerAccount = 'qwexfhmvvdci'
      const txfeePayerPrivateKey = '5KV84hXSJvu3nfqb9b1raRMnzvULaHH6Fsaz4xBZG2QbfPwMg76' // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db

      const confDefaults = {
        networkId,
        registryContract,
        rpcEndpoint,
        txfeePayerAccount,
        txfeePayerPrivateKey,
      }
      const conf = {
        ...confDefaults,
        did: `did:infra:${networkId}:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`,
        didOwnerPrivateKey: 'PVT_K1_2QUHdXAKxtfbCbFDL5FoVtLpPp6sWQpXzRpW7dXXZFS2qVqFFn'
      }

      const didApi = new InfraDID(conf);
      didApi.revokePubKeyDID();

      expect(verifier.isRevoked(conf.did)).rejects.toBeFalsy();
    })

    describe("is Valid Function", () => {
        const networkId = '01'
        const registryContract = 'fmapkumrotfc'
        const rpcEndpoint = 'https://api.testnet.eos.io'
        const txfeePayerAccount = 'qwexfhmvvdci'
        const txfeePayerPrivateKey = '5KV84hXSJvu3nfqb9b1raRMnzvULaHH6Fsaz4xBZG2QbfPwMg76' // EOS6hiaAMKE7iHd7BgfoKJ63JCFNoser35hu3KNsjLEgo8TV4P4db

        const confDefaults = {
            networkId,
            registryContract,
            rpcEndpoint,
            txfeePayerAccount,
            txfeePayerPrivateKey,
        }
        const conf = {
            ...confDefaults,
            did: `did:infra:${networkId}:PUB_K1_5TaEgpVur391dimVnFCDHB122DXYBbwWdKUpEJCNv3ko1KMYwz`,
            didOwnerPrivateKey: 'PVT_K1_2QUHdXAKxtfbCbFDL5FoVtLpPp6sWQpXzRpW7dXXZFS2qVqFFn'
        }
        it("Error : Signer is not the subject of VC", async () => {
            const holder = "did:infra:01:PUB_K1_7kF9Qay9V2dRnXJQy4tz6YTmb1mdYDchXvsQtQNnaXRcaVVuLa"

            const issuerDID = InfraDID.createPubKeyDIDsecp256k1('01');
            verifier.knownIssuers.push({id:'new Issuer', did:issuerDID.did})

            const issuerApi = new InfraDID(conf);
            const issuer = issuerApi.getJwtVcIssuer()

            const credential : CredentialPayload = {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                id: 'http://example.vc/credentials/123532',
                type: ['VerifiableCredential', 'VaccinationCredential'],
                issuer: conf.did,
                // issuanceDate: '2021-03-17T12:17:26.000Z',
                issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
                credentialSubject: {
                    id: "did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr",
                    claim1: 'claim1_value',
                    claim2: 'claim2_value'
                }
            }
            const createdJWTvc = await createVerifiableCredentialJwt(credential,issuer);
            console.log(decodeJWT(createdJWTvc))
            try {
                await verifier.isValidVC(createdJWTvc,holder)
            } catch (err) {
                expect(err.message).toEqual(`Signer is not the subject of VC`);
            }
        })

        it("Error : Unknown Issuer", async () => {
            const issuerApi = new InfraDID(conf);
            const issuer = issuerApi.getJwtVcIssuer()

            const credential : CredentialPayload = {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                id: 'http://example.vc/credentials/123532',
                type: ['VerifiableCredential', 'VaccinationCredential'],
                issuer: conf.did,
                // issuanceDate: '2021-03-17T12:17:26.000Z',
                issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
                credentialSubject: {
                    id: "did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr",
                    claim1: 'claim1_value',
                    claim2: 'claim2_value'
                }
            }
            const createdJWTvc = await createVerifiableCredentialJwt(credential,issuer);
            console.log(decodeJWT(createdJWTvc))
            try {
                await verifier.isValidVC(createdJWTvc)
            } catch (err) {
                expect(err.message).toEqual(`Unknown Issuer`)
            }
        })
        test("Error : Deactivated Issuer", async () => {
            const issuerDID = InfraDID.createPubKeyDIDsecp256k1('01');
            verifier.knownIssuers.push({id:'will revoke', did:issuerDID.did})

            const issuerConf = {
                ...confDefaults,
                did: issuerDID.did,
                didOwnerPrivateKey: issuerDID.privateKey
            }

            console.log(verifier.knownIssuers)

            const issuerApi = new InfraDID(issuerConf);
            const issuer = issuerApi.getJwtVcIssuer()

            const credential : CredentialPayload = {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                id: 'http://example.vc/credentials/123532',
                type: ['VerifiableCredential', 'VaccinationCredential'],
                issuer: issuerDID.did,
                // issuanceDate: '2021-03-17T12:17:26.000Z',
                issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
                credentialSubject: {
                    id: "did:infra:01:PUB_K1_6XpzkXC8amUN1AQccYcVpRMBajq8b3HHhYJVZ4uJQ7pW9TJvmr",
                    claim1: 'claim1_value',
                    claim2: 'claim2_value'
                }
            }
            const createdJWTvc = await createVerifiableCredentialJwt(credential,issuer);
            issuerApi.revokePubKeyDID()
            console.log(decodeJWT(createdJWTvc))
            try {
                await verifier.isValidVC(createdJWTvc)
            } catch (err) {
                expect(err.message).toEqual(`Deactivated Issuer`);
            }
        })
        it("Error : Revoked VC", async () => {
            const issuerDID = InfraDID.createPubKeyDIDsecp256k1('01');
            verifier.knownIssuers.push({id:'Added Issuer', did:issuerDID.did})

            const issuerApi = new InfraDID(conf);
            const issuer = issuerApi.getJwtVcIssuer()

            const vcID_conf = {
                ...confDefaults,
                did: `did:infra:${networkId}:PUB_K1_8PwG7of5B8p9Mpaw6XzeyYtSWJyeSXVtxZhPHQC5eZxZCkqiLU`, //pubKeyDID.did,
                didOwnerPrivateKey: 'PVT_K1_tSwgNjuLyhyGo96qadzzqkaA5tfwMeAfreQzWo652gVPxiVLA', //pubKeyDID.privateKey,
            }
            const vcID_api = new InfraDID(vcID_conf);

            const credential : CredentialPayload = {
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                id: 'http://example.vc/credentials/123532',
                type: ['VerifiableCredential', 'VaccinationCredential'],
                issuer: conf.did,
                // issuanceDate: '2021-03-17T12:17:26.000Z',
                issuanceDate: new Date().toISOString(), //'2021-03-17T12:17:26.000Z',
                credentialSubject: {
                    id: vcID_conf.did,
                    claim1: 'claim1_value',
                    claim2: 'claim2_value'
                }
            }

            const createdJWTvc = await createVerifiableCredentialJwt(credential,issuer);
            vcID_api.revokePubKeyDID()
            console.log(decodeJWT(createdJWTvc))
            try {
                verifier.isValidVC(createdJWTvc);
            } catch (err) {
                expect(err.message).toEqual(`Revoked VC`);
            }
        })
        it("Return True", async () => {

        })
    } )

    it('function isValidVP', () => {
        expect(verifier.isValidVP(vpJWT)).toBeTruthy();
    })

})
