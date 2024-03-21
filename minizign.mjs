import fs from 'node:fs';

function checkResult(result) {
  switch (result) {
    case -1:
      throw new Error("Out of memory");
      break;
    case -2:
      throw new Error("Invalid Encoding");
      break;
    case -3:
      throw new Error("Invalid Character");
      break;
    case -4:
      throw new Error("Invalid Padding");
      break;
    case -5:
      throw new Error("No Space Left");
      break;
    case -6:
      throw new Error("Unsupported Algorithm");
      break;
    case -7:
      throw new Error("Key Id Mismatch");
      break;
    case -8:
      throw new Error("Signature Verification Failed");
      break;
    case -9:
      throw new Error("Non Canonical");
      break;
    case -10:
      throw new Error("Identity Element");
      break;
    case -11:
      throw new Error("Weak Public Key");
      break;
    default:
      // Do nothing
      break;
  }
}

export class Minizign {
  constructor() {
    this.asm = fs.readFileSync('./minizign.wasm');
    this.mod = WebAssembly.compile(this.asm);
    this.instance = null;
  } 
  async init() {
    this.mod = await this.mod;
    this.instance = await WebAssembly.instantiate(this.mod); 
  }
  getSlice(slice) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before getSlice');
    }

    const { index, length, capacity } = slice;
  
    const { memory } = this.instance.exports;
    const memoryView = new Uint8Array(memory.buffer);
    
    const subarray = memoryView.subarray(index, index + capacity);
    const used = subarray.subarray(0, length);
    const unused = subarray.subarray(length);

    return { all: subarray, used, unused };
  }
  encode(string) { 
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before encode');
    }

    const { memory, allocate } = this.instance.exports;
    const length = string.length * 3;
 
    const resultAlloc = allocate(length * 3); 
    checkResult(resultAlloc); 

    const memoryView = new Uint8Array(memory.buffer);
    const encoder = new TextEncoder(); 
    const { written } = encoder.encodeInto(string, memoryView.subarray(resultAlloc));

    return { index: resultAlloc, length: written, capacity: length };
  }
  dupe(array) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before dupe');
    }

    const { memory, allocate } = this.instance.exports;

    const resultAlloc = allocate(array.length); 
    checkResult(resultAlloc); 
 
    const memoryView = new Uint8Array(memory.buffer);
    memoryView.set(array, resultAlloc) 
    
    return { index: resultAlloc, length: array.length, capacity: array.length };
  }
  publicKey(base64String) {
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before publicKey');
    }

    const { publicKeyFromBase64 } = this.instance.exports;

    const encodedString = this.encode(base64String);

    const resultFromBase64 = publicKeyFromBase64(encodedString.index, encodedString.length); 
    checkResult(resultFromBase64);

    return new PublicKey(this, resultFromBase64, encodedString);
  }
  signature(sigArray) { 
    if (this.instance === null) {
      throw new Error('Minizign.init() must be called before signature');
    }

    const { signatureDecode } = this.instance.exports;

    const dupedArray = this.dupe(sigArray);

    const resultDecode = signatureDecode(dupedArray.index, dupedArray.length); 
    checkResult(resultDecode);

    return new Signature(this, resultDecode, dupedArray);
  }
}

export class Signature {
  constructor(minizign, index, slice) {
    this.minizign = minizign;
    this.index = index;
    this.slice = slice;
  }
  deinit() {
    const instance = this.minizign.instance;
    instance.exports.signatureDeinit(this.index);
    instance.exports.free(this.slice.index, this.slice.capacity);
  }
}

export class PublicKey {
  constructor(minizign, index, string) {
    this.minizign = minizign;
    this.index = index;
    this.string = string;
  }
  verify(signature, file) {   
    if (!(this instanceof PublicKey)) {
      throw new Error('this must be an instance of PublicKey');
    }
    if (!(signature instanceof Signature)) {
      throw new Error('signature parameter must be an instance of Signature');
    }

    const instance = this.minizign.instance;

    const { publicKeyVerify } = instance.exports

    const dupedFile = this.minizign.dupe(file);
    this.file = dupedFile;
    
    const resultVerify = publicKeyVerify(this.index, signature.index, dupedFile.index, dupedFile.length);
    checkResult(resultVerify); 

    if (resultVerify !== 1) {
      throw new Error('Unexpected result from verifying');
    }
  }
  deinit() {
    const instance = this.minizign.instance;
    instance.exports.publicKeyDeinit(this.index);
    instance.exports.free(this.string.index, this.string.capacity);
    this.file && instance.exports.free(this.file.index, this.file.capacity);
  }
} 
