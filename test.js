const multisigHmac = require('.')

const k1 = multisigHmac.keygen(0)
const k2 = multisigHmac.keygen(1)
const k3 = multisigHmac.keygen(2)

const data = Buffer.from('hello world')
const nonce = Buffer.from((1).toString())

const s1 = multisigHmac.sign(k1, data, nonce)
const s2 = multisigHmac.sign(k2, data, nonce)
const s3 = multisigHmac.sign(k3, data, nonce)

const combined = multisigHmac.combine([s1, s2, s3])

console.log(multisigHmac.verify([k1, k2, k3], combined, data, nonce, 2))
