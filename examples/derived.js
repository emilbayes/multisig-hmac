const multisigHmac = require('..')

// Generate a master seed, which needs to be stored securely
// This seed must NOT be shared with any other party
const seed = multisigHmac.seedgen()

const k1 = multisigHmac.deriveKey(seed, '1')
const k2 = multisigHmac.deriveKey(seed, '2')
const k3 = multisigHmac.deriveKey(seed, '3')

// Sign by each client with 2-of-3
const data = Buffer.from('Hello world')
const nonce = Buffer.from(Date.now().toString())

const s1 = multisigHmac.sign(k1, data, nonce)
const s3 = multisigHmac.sign(k2, data, nonce)

const signature = multisigHmac.combine([s1, s3])

// Verify on the server, but now keys are dynamically derived
const threshold = 2
const verified = multisigHmac.verifyDerived(seed, signature, data, nonce, threshold)
console.log(verified)
