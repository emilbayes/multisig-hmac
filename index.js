const crypto = require('crypto')
const assert = require('nanoassert')
const popcnt32 = require('popcnt32')

class MultisigHMAC {
  constructor (alg = PRIMITIVE) {
    switch (alg) {
      case 'sha256':
        this._alg = SHA256_PRIMITIVE
        this._keyBytes = SHA256_KEYBYTES
        this._bytes = SHA256_BYTES
        break
      case 'sha384':
        this._alg = SHA384_PRIMITIVE
        this._keyBytes = SHA384_KEYBYTES
        this._bytes = SHA384_BYTES
        break
      case 'sha512':
        this._alg = SHA512_PRIMITIVE
        this._keyBytes = SHA512_KEYBYTES
        this._bytes = SHA512_BYTES
        break
      case 'sha512_256':
        this._alg = SHA512_256_PRIMITIVE
        this._keyBytes = SHA512_256_KEYBYTES
        this._bytes = SHA512_256_BYTES
        break
      default:
        assert(false, 'Unknown alg used')
    }

    this._scratch = Buffer.alloc(7 + 4, 'derived')
  }

  keygen (index, buf) {
    assert(index === index >>> 0, 'index must be valid uint32')
    if (buf == null) buf = Buffer.alloc(this._keyBytes)
    assert(Buffer.isBuffer(buf), 'buf must be Buffer')
    assert(buf.byteLength >= this._keyBytes, 'buf must be at least KEYBYTES long')

    return { index, key: crypto.randomFillSync(buf, 0, this._keyBytes) }
  }

  seedgen (buf) {
    if (buf == null) buf = Buffer.alloc(this._keyBytes)
    assert(Buffer.isBuffer(buf), 'buf must be Buffer')
    assert(buf.byteLength >= this._keyBytes, 'buf must be at least KEYBYTES long')

    return crypto.randomFillSync(buf, 0, this._keyBytes)
  }

  deriveKey (masterSeed, index, buf) {
    assert(Buffer.isBuffer(masterSeed), 'masterSeed must be Buffer')
    assert(masterSeed.byteLength === this._keyBytes, 'masterSeed must KEYBYTES long')
    assert(index === index >>> 0, 'index must be valid uint32')
    if (buf == null) buf = Buffer.alloc(this._bytes)
    assert(Buffer.isBuffer(buf), 'buf must be Buffer')
    assert(buf.byteLength >= this._bytes, 'buf must be at least BYTES long')

    this._scratch.writeUInt32LE(index, 7)
    return { index, key: crypto.createHmac('sha256', masterSeed).update(this._scratch).digest(buf) }
  }

  sign (keyObj, data, buf) {
    assert(keyObj.index === keyObj.index >>> 0, 'keyObj.index must be valid uint32')
    assert(Buffer.isBuffer(keyObj.key), 'keyObj.key must be Buffer')
    assert(keyObj.key.byteLength === this._keyBytes, 'keyObj.key must be KEYBYTES long')
    assert(typeof data === 'string' || Buffer.isBuffer(data), 'data must be String or Buffer')

    if (buf == null) buf = Buffer.alloc(this._bytes)
    assert(Buffer.isBuffer(buf), 'buf must be Buffer')
    assert(buf.byteLength >= this._bytes, 'buf must be at least BYTES long')

    return {
      bitfield: 1 << keyObj.index,
      signature: crypto.createHmac('sha256', keyObj.key).update(data).digest(buf)
    }
  }

  combine (signatures, buf) {
    assert(signatures.every(s => s.bitfield === s.bitfield >>> 0), 'one or more signatures had signature.bitfield not be uint32')
    assert(signatures.every(s => s.signature.byteLength === this._bytes), 'one or more signatures had signature.signature byteLength not be BYTES long')
    const res = {
      bitfield: xorInts(signatures.map(s => s.bitfield)),
      signature: xorBufs(signatures.map(s => s.signature), buf)
    }

    assert(popcnt32(res.bitfield) === signatures.length, 'one or more signatures cancelled out')
    assert(res.signature.reduce((s, b) => s + b, 0) > 0, 'one or more signatures cancelled out')

    return res
  }

  verify (keys, signature, data, threshold, sigScratchBuf) {
    assert(threshold > 0, 'threshold must be at least 1')
    assert(threshold === threshold >>> 0, 'threshold must be valid uint32')
    var bitfield = signature.bitfield
    const nKeys = popcnt32(bitfield)
    const highestKey = 32 - Math.clz32(bitfield)
    assert(keys.length >= nKeys && keys.length >= highestKey, 'Not enough keys given based on signature.bitfield')
    assert(typeof data === 'string' || Buffer.isBuffer(data), 'data must be String or Buffer')

    if (nKeys < threshold) return false

    const usedKeys = indexes(bitfield)
    var sig = Buffer.from(signature.signature)
    for (var i = 0; i < usedKeys.length; i++) {
      const key = keys[usedKeys[i]]
      const keySig = this.sign(key, data, sigScratchBuf)

      sig = xorBufs([sig, keySig.signature])
      bitfield ^= keySig.bitfield
    }

    return bitfield === 0 && sig.every(b => b === 0)
  }

  verifyDerived (masterSeed, signature, data, threshold, keyScratchBuf, sigScratchBuf) {
    assert(Buffer.isBuffer(masterSeed), 'masterSeed must be Buffer')
    assert(masterSeed.byteLength === this._keyBytes, 'masterSeed must KEYBYTES long')
    assert(threshold > 0, 'threshold must be at least 1')
    assert(threshold === threshold >>> 0, 'threshold must be valid uint32')
    var bitfield = signature.bitfield
    assert(typeof data === 'string' || Buffer.isBuffer(data), 'data must be String or Buffer')

    const usedKeys = indexes(bitfield)

    if (sigScratchBuf == null) sigScratchBuf = Buffer.from(signature)
    else sigScratchBuf.set(signature)

    for (var i = 0; i < usedKeys.length; i++) {
      const key = this.deriveKey(masterSeed, usedKeys[i])
      const keySig = this.sign(key, data, keyScratchBuf)

      xorBufs([keySig.signature], sigScratchBuf)
      bitfield ^= keySig.bitfield
    }

    return bitfield === 0 && sigScratchBuf.every(b => b === 0)
  }
}

const SHA256_KEYBYTES = MultisigHMAC.SHA256_KEYBYTES = 512 / 8
const SHA256_BYTES = MultisigHMAC.SHA256_BYTES = 256 / 8
const SHA256_PRIMITIVE = MultisigHMAC.SHA256_PRIMITIVE = 'sha256'
const SHA384_KEYBYTES = MultisigHMAC.SHA384_KEYBYTES = 1024 / 8
const SHA384_BYTES = MultisigHMAC.SHA384_BYTES = 384 / 8
const SHA384_PRIMITIVE = MultisigHMAC.SHA384_PRIMITIVE = 'sha384'
const SHA512_KEYBYTES = MultisigHMAC.SHA512_KEYBYTES = 1024 / 8
const SHA512_BYTES = MultisigHMAC.SHA512_BYTES = 512 / 8
const SHA512_PRIMITIVE = MultisigHMAC.SHA512_PRIMITIVE = 'sha512'
const SHA512_256_KEYBYTES = MultisigHMAC.SHA512_256_KEYBYTES = 1024 / 8
const SHA512_256_BYTES = MultisigHMAC.SHA512_256_BYTES = 256 / 8
const SHA512_256_PRIMITIVE = MultisigHMAC.SHA512_256_PRIMITIVE = 'sha512_256'

const KEYBYTES = MultisigHMAC.KEYBYTES = SHA256_KEYBYTES
const BYTES = MultisigHMAC.BYTES = SHA256_BYTES
const PRIMITIVE = MultisigHMAC.PRIMITIVE = SHA256_PRIMITIVE

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

module.exports = MultisigHMAC
