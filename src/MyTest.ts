import Verifier, { VerifierConfig } from './index';
import { decodeJWT } from 'did-jwt';
import { Resolver } from 'did-resolver';
import { getResolver } from 'infra-did-resolver';

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
  knownIssuers: [ { id: "kdca", did : 'did:infra:01:PUB_K1_6dPEaVqyhUXNyCfTnK77TBbgf9Gghkq4ANikTz3cJU9YWwKUyn'}],
}

config.resolver = new Resolver(getResolver(config.networkConfig));

const verifier = new Verifier(config);
const vcJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpYXQiOjE2MjM5MDI1NzYsImF1ZCI6ImRpZDppbmZyYTowMTpQVUJfSzFfNlhwemtYQzhhbVVOMUFRY2NZY1ZwUk1CYWpxOGIzSEhoWUpWWjR1SlE3cFc5VEp2bXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSIsImNsYWltMSI6ImNsYWltMV92YWx1ZSIsImNsYWltMiI6ImNsYWltMl92YWx1ZSJ9fSwiaXNzIjoiZGlkOmluZnJhOjAxOlBVQl9LMV84UHdHN29mNUI4cDlNcGF3Nlh6ZXlZdFNXSnllU1hWdHhaaFBIUUM1ZVp4WkNrcWlMVSJ9.u0rUV911N6EcgE_kdiXoXURv3UeaFFKZYQ4Tf5mrZ-C6y8qSDPeeLLIQUuk8CPjB-GliX10DPXm8MiMvb5pbjg';

verifier.isValidVC(vcJWT).then(function(result) {
  console.log(result)
})



