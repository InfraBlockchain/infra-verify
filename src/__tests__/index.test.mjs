import Verifier, { VerifierConfig } from '../index';
import { Resolver } from 'did-resolver';
import { getResolver } from 'infra-did-resolver';
import { ConfigurationOptions } from 'infra-did-resolver';

describe('Initialize Verifier', () => {
    const config: VerifierConfig = {
        networkConfig: {
            networks: [
                {
                    networkId: 'test01',
                    registryContract: 'infradidregi',
                    rpcEndpoint: 'https://api.testnet.infrablockchain.com'
                },
            ],
        },
        did: undefined,
        knownIssuer: undefined,
    }
    it('initialize with resolver', () => {
        const verifier = new Verifier(config);
        // console.log(verifier);
        expect(1).toBe(1);
    })

    beforeAll(async () => {
        // config.resolver = new Resolver(getResolver(config.networkConfig));
    })
})