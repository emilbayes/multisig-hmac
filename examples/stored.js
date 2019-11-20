const multisigHmac = require('..')

// generate keys, which need to be stored securely
// and need to be shared securely with each party
const k1 = multisigHmac.keygen(1)
const k2 = multisigHmac.keygen(2)
const k3 = multisigHmac.keygen(3)

// Sign by each client with 2-of-3
const data = Buffer.from('Hello world')
const nonce = Buffer.from(Date.now().toString())

const s1 = multisigHmac.sign(k1, data, nonce)
const s3 = multisigHmac.sign(k3, data, nonce)

const signature = multisigHmac.combine([s1, s3])

// Verify on the server
const threshold = 2
const keys = [k1, k2, k3]

const verified = multisigHmac.verify(keys, signature, data, nonce, threshold)
console.log(verified)
