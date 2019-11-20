# `multisig-hmac`

> Multisig scheme for HMAC authentication

## Usage

Key managment can happen in either of two modes, either by storing every of the
component keys, or by storing a single master seed and using that to derive keys
ad hoc.

Using stored keys:

```js
const multisigHmac = require('multisig-hmac')

// generate keys, which need to be stored securely
// and need to be shared securely with each party
const k1 = multisigHmac.keygen(1)
const k2 = multisigHmac.keygen(2)
const k3 = multisigHmac.keygen(3)

// Sign by each client with 2-of-3
const data = Buffer.from('Hello world')

// Notice no mention of nonce here. The data can follow whatever format you
// desire, but should include a nonce
const s1 = multisigHmac.sign(k1, data)
const s3 = multisigHmac.sign(k3, data)

const signature = multisigHmac.combine([s1, s3])

// Verify on the server
const threshold = 2
const keys = [k1, k2, k3]
const verified = multisigHmac.verify(keys, signature, data, threshold)
console.log(verified)
```

Using a derived master key:

```js
const multisigHmac = require('multisig-hmac')

// Generate a master seed, which needs to be stored securely
// This seed must NOT be shared with any other party
const seed = multisigHmac.seedgen()

const k1 = multisigHmac.deriveKey(seed, 1)
const k2 = multisigHmac.deriveKey(seed, 2)
const k3 = multisigHmac.deriveKey(seed, 3)

// Sign by each client with 2-of-3
const data = Buffer.from('Hello world')

// Notice no mention of nonce here. The data can follow whatever format you
// desire, but should include a nonce
const s1 = multisigHmac.sign(k1, data)
const s3 = multisigHmac.sign(k3, data)

const signature = multisigHmac.combine([s1, s3])

// Verify on the server, but now keys are dynamically derived
const threshold = 2
const verified = multisigHmac.verifyDerived(seed, signature, data, threshold)
console.log(verified)
```

## API

### `const key = multisigHmac.keygen()`

### `const masterSeed = multisigHmac.seedgen()`

### `const key = multisigHmac.deriveKey(masterSeed, index)`

### `const signature = multisigHmac.sign(key, data)`

### `const aggSignature = multisigHmac.combine([ signatures... ])`

### `const valid = multisigHmac.verify([keys...], aggSignature, data, threshold)`

### `const valid = multisigHmac.verifyDerived(masterSeed, aggSignature, data, threshold)`

## Install

```sh
npm install multisig-hmac
```

## License

[ISC](LICENSE)
