import fs from 'node:fs';

export default class Minizign {
  constructor() {
    this.asm = fs.readFileSync('./minizign.wasm');
    this.mod = WebAssembly.compile(this.asm);
  } 
  async verify(publicKey, signature, file) {  
    this.instance = await WebAssembly.instantiate(await this.mod);
    const { 
      memory, 
      allocateBuffer, 
      publicKeyFromBase64, 
      signatureDecode, 
      publicKeyVerifySignature 
    } = this.instance.exports;

    const bufferOffsetPKBytes = allocateBuffer(publicKey.length * 3);
    const bufferOffsetSigBytes = allocateBuffer(signature.length);
    const bufferOffsetFileBytes = allocateBuffer(file.length);

    if (bufferOffsetPKBytes == 0 || bufferOffsetSigBytes == 0 || bufferOffsetFileBytes == 0) {
      throw new Error('Failed to allocate buffers!');
    }

    const memoryView = new Uint8Array(memory.buffer);
    const encoder = new TextEncoder();

    const { written: sizePK } = encoder.encodeInto(publicKey, memoryView.subarray(bufferOffsetPKBytes));
    memoryView.set(signature, bufferOffsetSigBytes);
    memoryView.set(file, bufferOffsetFileBytes);
 
    const optPK = publicKeyFromBase64(bufferOffsetPKBytes, sizePK);

    if (optPK === 0) {
      throw new Error('Failed to decode public key!');
    }

    const optSig = signatureDecode(bufferOffsetSigBytes, signature.length);

    if (optSig === 0) {
      throw new Error('Failed to decode signature!');
    }

    const isVerified = publicKeyVerifySignature(optPK, optSig, bufferOffsetFileBytes, file.length);
    if (isVerified !== 1) {
      throw new Error('Verification failed!');
    }
  }
}

// export function verify(publicKey, signature, file) {
//   const instance = await WebAssembly.instantiate(mod);
//   const { 
//     memory, 
//     allocateBuffer, 
//     publicKeyFromBase64, 
//     signatureDecode, 
//     publicKeyVerifySignature 
//   } = instance.exports;
// 
//   const bufferOffsetPKBytes = allocateBuffer(publicKey.length * 3);
//   const bufferOffsetSigBytes = allocateBuffer(signature.length);
//   const bufferOffsetFileBytes = allocateBuffer(file.length);
// 
//   if (bufferOffsetPKBytes == 0 || bufferOffsetSigBytes == 0 || bufferOffsetFileBytes == 0) {
//     return false;
//   }
// 
//   const memoryView = new Uint8Array(memory.buffer);
//   const encoder = new TextEncoder();
// 
//   const { written: sizePK } = encoder.encodeInto(publicKey, memoryView.subarray(bufferOffsetPKBytes));
//   memoryView.set(signature, bufferOffsetSigBytes);
//   memoryView.set(file, bufferOffsetFileBytes);
//  
//   const optPK = publicKeyFromBase64(bufferOffsetPKBytes, sizePK);
// 
//   if (optPK === 0) {
//     return false;
//   }
// 
//   const optSig = signatureDecode(bufferOffsetSigBytes, signature.length);
// 
//   if (optSig === 0) {
//     return false;
//   }
// 
//   const isVerified = publicKeyVerifySignature(optPK, optSig, bufferOffsetFileBytes, file.length);
//   return isVerified !== 0;
// }

// WebAssembly.instantiate(source).then((result) => {
//   const { memory, allocateBuffer, publicKeyFromBase64, signatureDecode, publicKeyVerifySignature } = result.instance.exports;

//   const publicKey = 'RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U';
//   const signature = fs.readFileSync('zig-linux-x86_64-0.12.0-dev.3180+83e578a18.tar.xz.minisig');
//   const file = fs.readFileSync('zig-linux-x86_64-0.12.0-dev.3180+83e578a18.tar.xz');

//   const bufferOffsetPKBytes = allocateBuffer(publicKey.length * 3);
//   const bufferOffsetSigBytes = allocateBuffer(signature.length);
//   const bufferOffsetFileBytes = allocateBuffer(file.length);

//   if (bufferOffsetPKBytes == 0 || bufferOffsetSigBytes == 0 || bufferOffsetFileBytes == 0) {
//     console.log("Couldn't allocate memory");
//     return;
//   }

//   const memoryView = new Uint8Array(memory.buffer);
//   const encoder = new TextEncoder();

//   const { written: sizePK } = encoder.encodeInto(publicKey, memoryView.subarray(bufferOffsetPKBytes));
//   memoryView.set(signature, bufferOffsetSigBytes);
//   memoryView.set(file, bufferOffsetFileBytes);
 
//   const optPK = publicKeyFromBase64(bufferOffsetPKBytes, sizePK);

//   if (optPK === 0) {
//     console.log("Unable to decode Public Key");
//     return;
//   }

//   const optSig = signatureDecode(bufferOffsetSigBytes, signature.length);

//   if (optSig === 0) {
//     console.log("Unable to decode Signature");
//     return;
//   }

//   const isVerified = publicKeyVerifySignature(optPK, optSig, bufferOffsetFileBytes, file.length);

//   if (isVerified !== 0) {
//     console.log("Signature matches");
//   } else { 
//     console.log("ERROR: Signature and Public Key do not match!");
//   }
// });

