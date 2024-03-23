/** @module minizign */
import wasmModule from './minizign.wasm'

/** 
 * @throws will throw error if argument is an error code
 */
function checkResult (result) {
  switch (result) {
    case -1:
      throw new Error('Out of memory')
    case -2:
      throw new Error('Invalid Encoding')
    case -3:
      throw new Error('Invalid Character')
    case -4:
      throw new Error('Invalid Padding')
    case -5:
      throw new Error('No Space Left')
    case -6:
      throw new Error('Unsupported Algorithm')
    case -7:
      throw new Error('Key Id Mismatch')
    case -8:
      throw new Error('Signature Verification Failed')
    case -9:
      throw new Error('Non Canonical')
    case -10:
      throw new Error('Identity Element')
    case -11:
      throw new Error('Weak Public Key')
    default:
      // Do nothing
  }
}

/** Top-level class providing high-level interface */
export class Minizign {
  constructor () {
    this.mod = WebAssembly.compile(wasmModule)
    this.instance = null
  }

  /** Initializes the WebAssembly module */
  async init () {
    this.mod = await this.mod
    this.instance = await WebAssembly.instantiate(this.mod)
  }

  /**
   * @param slice - Index + Length into WASM memory
   * @return Uint8Array referencing WASM memory
   */
  getSlice (slice) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before getSlice')
    }

    const { index, length, capacity } = slice

    const { memory } = this.instance.exports
    const memoryView = new Uint8Array(memory.buffer)

    const subarray = memoryView.subarray(index, index + capacity)
    const used = subarray.subarray(0, length)
    const unused = subarray.subarray(length)

    return { all: subarray, used, unused }
  }

  /**
   * Encodes a JavaScript string into the WASM memory as UTF8 
   * @param {string} string - The string to encode
   * @return Slice of the encoded string
   */
  encode (string) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before encode')
    }

    const { memory, allocate } = this.instance.exports
    const length = string.length * 3

    const resultAlloc = allocate(length * 3)
    checkResult(resultAlloc)

    const memoryView = new Uint8Array(memory.buffer)
    const encoder = new TextEncoder()
    const { written } = encoder.encodeInto(string, memoryView.subarray(resultAlloc))

    return { index: resultAlloc, length: written, capacity: length }
  }

  /** 
   * Copies a Uint8Array into the WASM memory 
   * @param {Uint8Array} array - Array to copy
   * @return Slice of the copied array
   */
  dupe (array) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before dupe')
    }

    const { memory, allocate } = this.instance.exports

    const resultAlloc = allocate(array.length)
    checkResult(resultAlloc)

    const memoryView = new Uint8Array(memory.buffer)
    memoryView.set(array, resultAlloc)

    return { index: resultAlloc, length: array.length, capacity: array.length }
  }

  /** 
   * @param {string} base64String - minisgn public key, base64 encoded 
   * @return {PublicKey}
   */
  publicKey (base64String) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before publicKey')
    }

    const { publicKeyFromBase64 } = this.instance.exports

    const encodedString = this.encode(base64String)

    const resultFromBase64 = publicKeyFromBase64(encodedString.index, encodedString.length)
    checkResult(resultFromBase64)

    return new PublicKey(this, resultFromBase64, encodedString)
  }

  /** 
   * @param {Uint8Array} sigArray - minisgn signature as array of bytes
   * @return {Signature}
   */
  signature (sigArray) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before signature')
    }

    const { signatureDecode } = this.instance.exports

    const dupedArray = this.dupe(sigArray)

    const resultDecode = signatureDecode(dupedArray.index, dupedArray.length)
    checkResult(resultDecode)

    return new Signature(this, resultDecode, dupedArray)
  }
}

/** A decoded minisign signature */
export class Signature {
  constructor (minizign, index, slice) {
    this.minizign = minizign
    this.index = index
    this.slice = slice
  }

  /** 
   * @return {string} Returns the signatures trusted comment
   */
  getTrustedComment () {
    const instance = this.minizign.instance
    const { memory, signatureGetTrustedComment, signatureFreeTrustedComment } = instance.exports

    const result = signatureGetTrustedComment(this.index)
    checkResult(result)

    const memoryView = new Uint8Array(memory.buffer)
    const dataview = new DataView(memory.buffer)

    const littleEndian = true
    const index = dataview.getUint32(result, littleEndian)
    const length = dataview.getUint32(result + 4, littleEndian)

    // DECODE
    const decoder = new TextDecoder()
    const comment = decoder.decode(memoryView.subarray(index, index + length))

    signatureFreeTrustedComment(result)

    return comment
  }
  
  /** Frees the WASM memory associated with object */
  deinit () {
    const instance = this.minizign.instance
    instance.exports.signatureDeinit(this.index)
    instance.exports.free(this.slice.index, this.slice.capacity)
  }
}

/** A decoded minisign public key */
export class PublicKey {
  constructor (minizign, index, string) {
    this.minizign = minizign
    this.index = index
    this.string = string
  }

  /**
   * @param {Signature} signature - A minisign signature for a file
   * @return {Verifier} A verifier that can be incrementally updated
   */
  verifier (signature) {
    const instance = this.minizign.instance
    const { publicKeyVerifier } = instance.exports

    if (!(signature instanceof Signature)) {
      throw new Error('signature parameter must be an instance of Signature')
    }

    const resultVerifier = publicKeyVerifier(this.index, signature.index)
    checkResult(resultVerifier)

    return new Verifier(this.minizign, resultVerifier)
  }

  /**
   * @param {Signature} signature - A minisign signature for file
   * @param {Uint8Array} buffer - The signed file
   * @throw exception when signature fails verification
   */
  verify (signature, buffer) {
    if (!(this instanceof PublicKey)) {
      throw new Error('this must be an instance of PublicKey')
    }
    if (!(signature instanceof Signature)) {
      throw new Error('signature parameter must be an instance of Signature')
    }

    const verifier = this.verifier(signature)

    verifier.update(buffer)
    verifier.verify()
  }

  /** Free WASM memory associated with object */
  deinit () {
    const instance = this.minizign.instance
    instance.exports.publicKeyDeinit(this.index)
    instance.exports.free(this.string.index, this.string.capacity)
  }
}

/** Allows incrementally hashing the file to verify */
export class Verifier {
  constructor (minizign, index) {
    this.minizign = minizign
    this.index = index
    this.bufferLength = 2 ** 10
    this.buffer = minizign.instance.exports.allocate(this.bufferLength)
    checkResult(this.buffer)
  }

  /**
   * @param {Uint8Array} slice - add contents of slice into hash
   */
  update (slice) {
    if (!(slice instanceof Buffer)) {
      throw new Error('Invalid argument passed to Verifier.update')
    }
    const { memory, verifierUpdate } = this.minizign.instance.exports
    const memoryView = new Uint8Array(memory.buffer)
    const buffer = memoryView.subarray(this.buffer, this.buffer + this.bufferLength)
    let i = 0
    while (i < slice.length) {
      const end = Math.min(slice.length, i + this.bufferLength)
      const length = end - i
      const sub = slice.subarray(i, end)
      buffer.set(sub)
      verifierUpdate(this.index, this.buffer, length)
      i += length
    }
  }

  /**
   * Call after calling update for every part of the file.
   * @throw exception when signature fails verification
   */
  verify () {
    const { verifierVerify } = this.minizign.instance.exports
    const resultVerify = verifierVerify(this.index)
    checkResult(resultVerify)

    if (resultVerify !== 1) {
      throw new Error('Unexpected result from verifying')
    }
  }

  /** Frees WASM memory associated with object */
  deinit () {
    const instance = this.minizign.instance
    instance.exports.verifierDeinit(this.index)
    instance.exports.free(this.buffer, 2 ** 10)
  }
}
