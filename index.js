const crypto = require('crypto')
const assert = require('nanoassert')
const popcnt32 = require('popcnt32')

const KEYBYTES = 512 / 8
const BYTES = 256 / 8

function keygen (index, buf) {
  assert(index === index >>> 0, 'index must be valid uint32')
  if (buf == null) buf = Buffer.alloc(KEYBYTES)
  assert(Buffer.isBuffer(buf), 'buf must be Buffer')
  assert(buf.byteLength >= KEYBYTES, 'buf must be at least KEYBYTES long')

  return { index, key: crypto.randomFillSync(buf, 0, KEYBYTES) }
}

function seedgen (buf) {
  if (buf == null) buf = Buffer.alloc(KEYBYTES)
  assert(Buffer.isBuffer(buf), 'buf must be Buffer')
  assert(buf.byteLength >= KEYBYTES, 'buf must be at least KEYBYTES long')

  return crypto.randomFillSync(buf, 0, KEYBYTES)
}

const scratch = Buffer.alloc(7 + 4, 'derived')
function deriveKey (masterSeed, index, buf) {
  assert(Buffer.isBuffer(masterSeed), 'masterSeed must be Buffer')
  assert(masterSeed.byteLength === KEYBYTES, 'masterSeed must KEYBYTES long')
  assert(index === index >>> 0, 'index must be valid uint32')
  if (buf == null) buf = Buffer.alloc(BYTES)
  assert(Buffer.isBuffer(buf), 'buf must be Buffer')
  assert(buf.byteLength >= BYTES, 'buf must be at least BYTES long')

  scratch.writeUInt32LE(index, 7)
  return { index, key: crypto.createHmac('sha256', masterSeed).update(scratch).digest(buf) }
}

function sign (keyObj, data, buf) {
  assert(keyObj.index === keyObj.index >>> 0, 'keyObj.index must be valid uint32')
  assert(Buffer.isBuffer(keyObj.key), 'keyObj.key must be Buffer')
  assert(keyObj.key.byteLength === KEYBYTES, 'keyObj.key must be KEYBYTES long')
  assert(typeof data === 'string' || Buffer.isBuffer(data), 'data must be String or Buffer')

  if (buf == null) buf = Buffer.alloc(BYTES)
  assert(Buffer.isBuffer(buf), 'buf must be Buffer')
  assert(buf.byteLength >= BYTES, 'buf must be at least BYTES long')

  return {
    bitfield: 1 << keyObj.index,
    signature: crypto.createHmac('sha256', keyObj.key).update(data).digest(buf)
  }
}

function combine (signatures, buf) {
  assert(signatures.every(s => s.bitfield === s.bitfield >>> 0), 'one or more signatures had signature.bitfield not be uint32')
  assert(signatures.every(s => s.signature.byteLength === BYTES), 'one or more signatures had signature.signature byteLength not be BYTES long')
  const res = {
    bitfield: xorInts(signatures.map(s => s.bitfield)),
    signature: xorBufs(signatures.map(s => s.signature), buf)
  }

  assert(popcnt32(res.bitfield) === signatures.length, 'one or more signatures cancelled out')
  assert(res.signature.reduce((s, b) => s + b, 0) > 0, 'one or more signatures cancelled out')

  return res
}

function verify (keys, signature, data, threshold, sigScratchBuf) {
  assert(threshold > 0, 'threshold must be at least 1')
  assert(threshold === threshold >>> 0, 'threshold must be valid uint32')
  var bitfield = signature.bitfield
  const nKeys = popcnt32(bitfield)
  assert(keys.length >= nKeys, 'Not enough keys given signature.bitfield')
  assert(typeof data === 'string' || Buffer.isBuffer(data), 'data must be String or Buffer')

  if (nKeys < threshold) return false

  const usedKeys = indexes(bitfield)
  var sig = Buffer.from(signature.signature)
  for (var i = 0; i < usedKeys.length; i++) {
    const key = keys[usedKeys[i]]
    const keySig = sign(key, data, sigScratchBuf)

    sig = xorBufs([sig, keySig.signature])
    bitfield ^= keySig.bitfield
  }

  return bitfield === 0 && sig.every(b => b === 0)
}

function verifyDerived (masterSeed, signature, data, threshold, keyScratchBuf, sigScratchBuf) {
  assert(Buffer.isBuffer(masterSeed), 'masterSeed must be Buffer')
  assert(masterSeed.byteLength === KEYBYTES, 'masterSeed must KEYBYTES long')
  assert(threshold > 0, 'threshold must be at least 1')
  assert(threshold === threshold >>> 0, 'threshold must be valid uint32')
  var bitfield = signature.bitfield
  assert(typeof data === 'string' || Buffer.isBuffer(data), 'data must be String or Buffer')

  const usedKeys = indexes(bitfield)

  if (sigScratchBuf == null) sigScratchBuf = Buffer.from(signature)
  else sigScratchBuf.set(signature)

  for (var i = 0; i < usedKeys.length; i++) {
    const key = deriveKey(masterSeed, usedKeys[i])
    const keySig = sign(key, data, keyScratchBuf)

    xorBufs([keySig.signature], sigScratchBuf)
    bitfield ^= keySig.bitfield
  }

  return bitfield === 0 && sigScratchBuf.every(b => b === 0)
}

function xorInts (ints) {
  return ints.reduce((r, i) => {
    r ^= i
    return r
  })
}

function xorBufs (bufs, buf) {
  if (buf == null) buf = Buffer.alloc(BYTES)
  assert(Buffer.isBuffer(buf), 'buf must be Buffer')
  assert(buf.byteLength >= BYTES, 'buf must be at least BYTES long')

  return bufs.reduce((r, b) => {
    for (var i = 0; i < r.byteLength; i++) {
      r[i] ^= b[i]
    }
    return r
  }, buf)
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
  KEYBYTES,
  keygen,
  seedgen,
  deriveKey,
  sign,
  combine,
  verify,
  verifyDerived
}
