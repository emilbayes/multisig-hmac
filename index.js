const crypto = require('crypto')

const BLOCK_SIZE = 512 / 8

function keygen (index) {
  return { index, key: crypto.randomBytes(BLOCK_SIZE) }
}

function deriveKey (masterSeed, index) {
  return { index, key: crypto.createHmac('sha256', masterSeed).update('derived').update(index).digest() }
}

function seedgen () {
  return crypto.randomBytes(BLOCK_SIZE)
}

function sign (keyObj, data, nonce) {
  return {
    bitfield: 1 << keyObj.index,
    signature: crypto.createHmac('sha256', keyObj.key).update(nonce).update(data).digest()
  }
}

function combine (signatures) {
  return {
    bitfield: xorInts(signatures.map(s => s.bitfield)),
    signature: xorBufs(signatures.map(s => s.signature))
  }
}

function verify (keys, signature, data, nonce, threshold) {
  var bitfield = signature.bitfield
  if (popcnt(bitfield) < threshold) return false

  const usedKeys = indexes(bitfield)
  var sig = Buffer.from(signature.signature)
  for (var i = 0; i < usedKeys.length; i++) {
    const key = keys[usedKeys[i]]
    const keySig = sign(key, data, nonce)

    sig = xorBufs([sig, keySig.signature])
    bitfield ^= keySig.bitfield
  }

  return bitfield === 0 && sig.every(b => b === 0)
}

function verifyDerived (masterSeed, signature, data, nonce, threshold) {
  var bitfield = signature.bitfield
  if (popcnt(bitfield) < threshold) return false

  const usedKeys = indexes(bitfield)
  var sig = Buffer.from(signature.signature)
  for (var i = 0; i < usedKeys.length; i++) {
    const key = deriveKey(masterSeed, '' + usedKeys[i])
    const keySig = sign(key, data, nonce)

    sig = xorBufs([sig, keySig.signature])
    bitfield ^= keySig.bitfield
  }

  return bitfield === 0 && sig.every(b => b === 0)
}

function xorInts (ints) {
  var int = 0
  for (var i = 0; i < ints.length; i++) {
    int ^= ints[i]
  }

  return int
}

function xorBufs (bufs) {
  const outSize = bufs.reduce((l, b) => Math.max(l, b.byteLength), 0)

  const buf = Buffer.alloc(outSize)
  for (var i = 0; i < bufs.length; i++) {
    for (var j = 0; j < bufs[i].length; j++) {
      buf[j] ^= bufs[i][j]
    }
  }

  return buf
}

function popcnt (int) {
  var cnt = 0
  while (int > 0) {
    cnt += int & 0x1
    int >>= 1
  }

  return cnt
}

function indexes (int) {
  var xs = []
  var i = 0
  while (int > 0) {
    if (int & 0x1) {
      xs.push(i)
    }
    int >>= 1
    i++
  }

  return xs
}

module.exports = {
  keygen,
  seedgen,
  deriveKey,
  sign,
  combine,
  verify,
  verifyDerived
}
