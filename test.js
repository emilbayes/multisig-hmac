const multisigHmac = require('.')

const k1 = multisigHmac.keygen(0)
const k2 = multisigHmac.keygen(1)
const k3 = multisigHmac.keygen(2)

const data = Buffer.from('hello world')

const s1 = multisigHmac.sign(k1, data)
const s2 = multisigHmac.sign(k2, data)
const s3 = multisigHmac.sign(k3, data)

const combined = multisigHmac.combine([s1, s2, s3])

console.log(multisigHmac.verify([k1, k2, k3], combined, data, 2))
