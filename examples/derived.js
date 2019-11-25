const MultisigHMAC = require('..')

const multisigHmac = new MultisigHMAC(MultisigHMAC.SHA256_PRIMITIVE)

// Generate a master seed, which needs to be stored securely
// This seed must NOT be shared with any other party
const seed = multisigHmac.seedgen()

const k1 = multisigHmac.deriveKey(seed, '1')
// const k2 = multisigHmac.deriveKey(seed, '2')
const k3 = multisigHmac.deriveKey(seed, '3')

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
