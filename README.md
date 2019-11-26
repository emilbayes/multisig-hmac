# `multisig-hmac`

> Multisig scheme for HMAC authentication

**Work in progress**

## Rationale

Many APIs use symmetric "signatures", through HMACs, of a nonce and the data to
be processed by a remote server. You always trust the receiving party to process
the data, as they are the trusted 3rd party with access to all keys, however the
external party, making the call to be processed, only has power over their own
keys. As an external party you might want to secure high sensitivity calls with
additional checks such as allowed IP ranges. Another check is that multiple
parties on the issuing side co-sign the request.

Imagine a `withdrawal` action on a bank or exchange or a `delete` call on a
cloud provider, which are both highly sensitive, "destructive" actions.
Using this multisig scheme, several separate entities on the calling party,
will have to agree to perform the action. This could be multiple servers or
people storing their own personal credentials.

This scheme takes each separate signature and a bitfield indicating the keys
used, which are combinable in an any order, allowing for simple threshold
schemes, or more advanced authentication flows.

Signatures made with this scheme are the same size as standard HMACs, with keys
being the same size. This module supports the SHA-2 suite of algorithms for HMAC
making it backwards compatible, in sizes, with existing HMAC authentication.
Implementing this scheme only requires storing the threshold for actions that
are multisig enabled.

## Usage

Key managment can happen in either of two modes, either by storing every of the
component keys, or by storing a single master seed and using that to derive keys
ad hoc.

Using stored keys:

```js
const MultisigHMAC = require('multisig-hmac')

const multisigHmac = new MultisigHMAC()

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
const MultisigHMAC = require('multisig-hmac')

const multisigHmac = new MultisigHMAC()

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

### Constants

* `MultisigHMAC.BYTES` signature length in bytes (default)
* `MultisigHMAC.KEYBYTES` key length in bytes (default)
* `MultisigHMAC.PRIMITIVE` is `sha256` (default)

Specific algorithms (support depends on your OpenSSL version):

* `MultisigHMAC.SHA256_BYTES` signature length in bytes
* `MultisigHMAC.SHA256_KEYBYTES` key length in bytes
* `MultisigHMAC.SHA256_PRIMITIVE` is `sha256`
* `MultisigHMAC.SHA384_BYTES` signature length in bytes
* `MultisigHMAC.SHA384_KEYBYTES` key length in bytes
* `MultisigHMAC.SHA384_PRIMITIVE` is `sha384`
* `MultisigHMAC.SHA512_BYTES` signature length in bytes
* `MultisigHMAC.SHA512_KEYBYTES` key length in bytes
* `MultisigHMAC.SHA512_PRIMITIVE` is `sha512`
* `MultisigHMAC.SHA512_256_BYTES` signature length in bytes
* `MultisigHMAC.SHA512_256_KEYBYTES` key length in bytes
* `MultisigHMAC.SHA512_256_PRIMITIVE` is `sha512_256` (also knowns as SHA512/256)

### `const n = MultisigHMAC.keysCount(bitfield)`

Returns the number of keys (ie. high bits) in `bitfield`. `bitfield` must be a
`uint32`.

Example: `assert(MultisigHMAC.keyIndexes(0b101), 2)`

### `const xs = MultisigHMAC.keyIndexes(bitfield)`

Returns the indexes of the keys (ie. high bits) in `bitfield` as an array.
`bitfield` must be a `uint32`.

Example: `assert(MultisigHMAC.keyIndexes(0b101), [0, 2])`

### `const multisigHmac = new MultisigHMAC([alg = MultisigHMAC.PRIMITIVE])`

Create a new instance of `MultisigHMAC`, which can be used as a global
singleton. Just sets the algorithm to be used for subsequent methods and
associated constants.

### `const key = multisigHmac.keygen(index, [buf])`

Generate a new cryptographically random key. Optionally pass a `Buffer` of
length `KEYBYTES` that the key will be written to. This will then be the same
`Buffer` in `key.key`.
Returns `{ index: uint32, key: Buffer }`.

*Note*: `index` should be counted from `0`

### `const masterSeed = multisigHmac.seedgen([buf])`

Generate a new cryptographically random master seed. Optionally pass a `Buffer`
of length `KEYBYTES` that the seed will be written to. This will then be the same
`Buffer` returned.

### `const key = multisigHmac.deriveKey(masterSeed, index, [buf])`

Derive a new sub key from a master seed. `index` must be a `uint32`, but in
practice you want to keep a much lower number, as the bitfield used with the
signature has as many bits as the largest index. A simple counter suffices.
Optionally pass a `Buffer` of length `KEYBYTES` that the key will be written to.
This will then be the same `Buffer` in `key.key`. Returns
`{ index: uint32, key: Buffer }`

*Note*: `index` should be counted from `0`

Keys are derived using a KDF based on HMAC:

```
 b[0...BYTES] = HMAC(Key = masterSeed, data = 'derive' || U32LE(index) || 0x00)
 b[BYTES...] = HMAC(Key = masterSeed, b[0...BYTES] || 0x01)
```

### `const signature = multisigHmac.sign(key, data, [buf])`

Independently sign `Buffer` `data` with `key`, using the optional `buf` to store
the signature. `buf` must be at least `BYTES` long. Returns
`{ bitfield: uint32, signature: Buffer }`.
This object can be passed to `combine()`

### `const signature = multisigHmac.combine([ signatures... ], [buf])`

Combine a list of signatures, which have all been signed independently. Only
include each signature once or they will cancel out. Optionally pass `buf`,
which will store the aggregate signature. This must be a `Buffer` of `BYTES`.
Signatures can be combined in any order and over several passes for more
advanced aggregation schemes. Returns `{ bitfield: uint32, signature: Buffer }`

### `const valid = multisigHmac.verify(keys, signature, data, threshold, [sigScratchBuf])`

Verify a `signature` of `data` against a list of `keys`, over a given
`threshold`. `keys` must be an `Array` of keys, from which the
`signature.bitfield` defines which must be verified. Optionally pass
`sigScratchBuf` which will be used for intermediate signature verification. This
`Buffer` must be `BYTES` long. Returns a `Boolean` for success.

### `const valid = multisigHmac.verifyDerived(masterSeed, signature, data, threshold, [keyScratchBuf], [sigScratchBuf])`

Verify a `signature` of `data` against dynamically derived keys from
`masterSeed`, over a given `threshold`. `masterSeed` must be an `Buffer` of
length `KEYBYTES`, from which the `signature.bitfield` defines which must be
derived and verified. Optionally pass `keyScratchBuf` for which the intermediate
keys are derived into and `sigScratchBuf` which will be used for intermediate
signature verification. These `Buffer`s must be `KEYBYTES` and `BYTES` long,
respectively. Returns a `Boolean` for success.

## Install

```sh
npm install multisig-hmac
```

## License

[ISC](LICENSE)
