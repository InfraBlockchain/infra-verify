import Verifier, { VerifierConfig } from '../index';
import { Resolver } from 'did-resolver';
import { getResolver } from 'infra-did-resolver';
import { ConfigurationOptions } from 'infra-did-resolver';

const testDID = 'did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn';
const testIssuers = [
    { id: "kdca", did : 'did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn'},
    { id: "moh", did : 'did:infra:01:PUB_K1_6bHihw3zP9VR1ezxZGay3wsoQxKQuzyCzkw9TJcWMHUtvLYtpJ'}]

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
