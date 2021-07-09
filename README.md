# infra-verify-js

## Introduce
Provides functions for validating verifiable credential and verifiable presentation.

## Installation
```
npm install infra-verify-js
```

## Usage

### Verify Configuration
```typescript
import Verifier, {VerifierConfig} from "infra-verify-js";

const issuerDID =[
    {
        id: 'kdca',
        did: 'did:infra:01:PUB_K1_5yeJywQqxEjZag6k4C9uXxtMednobVkzgdFxXom9RiEUYR1Hbu',
        privateKey: 'PVT_K1_Y76JJXw39bFPeAM9i5SbkDtjzLxBpQMhktmVUj6x9Y6BUgXKC'
    }
]

const verifierDID = {
    did: 'did:infra:01:PUB_K1_88APqaXVDMkBv2utSQC54vRpmzyjLe1BweGvLYBgGjTCf1eHVn',
    privateKey: 'PVT_K1_6xS23G7RgdGWsvwSfy8YKLPSHYUddDJC9R5H6xt8kgTTpzVkE'
}

const config : VerifierConfig = {
    networkConfig: {
        networks: [
            {
            networkId : '01',
            registryContract : 'fmapkumrotfc',
            rpcEndpoint : 'https://api.testnet.eos.io'
            }
        ]
    },
    did: verifierDID.did,
    knownIssuers: issuerDID
}

const verifier = new Verifier(config);
```


### Get verifiable credential claims(getVCClaims)
Extract claims in JWT format from the verifiable credential.
```typescript
const vcJWT = 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJpZCI6ImRpZDppbmZyYTowMTpQVUJfSzFfOFpnYnpRc1NvREd0QWE5M2hEOFdMdEJCWHk2VURuNWtpYzNaZ3FqMzRWQkZadDhYWE0iLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vY29vdi52Yy5pby9wZXJzb25hbCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiUGVyc29uYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6Iuq5gOy_oOu4jCJ9fSwibmJmIjoxNjI0NDY0ODM5LCJpc3MiOiJkaWQ6aW5mcmE6MDE6UFVCX0sxXzZXR3J2bnVHN3hGeENGQTRkUHJlZmg5M0hVZEc3ZDFmalVRTnNaWFE2SmZSQzZHM1pDIn0.XVXpj9MPm6lBUu1tDLHeDvWEfXU9vw79UWcvlocWZpuiaF774gNXpMPwsAExsGcaWaQvASUbjxm18meP22LqDQ'

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
}*/

console.log(verifier.getVCClaims(vcJWT))
```



### Verifiable credential and verifiable presentation validation(isValid)
Validate verifiable credentials or verifiable presentations in JWT format.

#### Verifiable credential validation(isValidVC)
* Verify that the holder's subject and verifiable credentials match.
* Verify that verifiable credential issued by known issuer.
* Verify that revoked issuer.
* Verify that revoked verifiable credential.
```typescript
verifier.isValid(vcJWT).then(result => {
    console.log(result)
}).catch(err => {
    console.log(err)
})

//const result = await verifier.isValid(vcJWT)
```

#### Verifiable presentation validation(isValidVP)
* Verify that revoked verifiable presentation.
* Validation of verifiable credentials embedded in verifiable presentations (equivalent to verifiable credentials validation)
```typescript
verifier.isValid(vpJWT).then(result => {
    console.log(result)
}).catch(err => {
    console.log(err)
})

//const result = await verifier.isValid(vpJWT)
```


### DID revoke check(isRevoked)
Resolve the DID to check whether it is revoke or not.
```typescript
verifier.isRevoked(verifierDID.did).then(result => {
    console.log(result)
}).catch(err => {
    console.log(err)
})

//const result = await verifier.isRevoked(verifierDID.did)
```


### Issuer check(isKnownIssuer)
Verify that it is a known (trusted) issuer
```typescript
console.log(verifier.isKnownIssuer(verifierDID.did))
```
