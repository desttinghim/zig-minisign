import fs from 'node:fs/promises';
import test from 'node:test'

import { Minizign, Signature } from './minizign.mjs';

const publicKey = 'RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U';
const publicKeyInvalid = 'RWSGOq2NVecA2UPNiBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U';
const signature = await fs.readFile('zig-linux-x86_64-0.12.0-dev.3180+83e578a18.tar.xz.minisig');
const file = await fs.readFile('zig-linux-x86_64-0.12.0-dev.3180+83e578a18.tar.xz');

test('valid public key, signature, and file', async (t) => { 
  const minizign = new Minizign();

  await minizign.init();
  
  let pk = null;
  let sig = null;
  try {
    pk = minizign.publicKey(publicKey);
    sig = minizign.signature(signature);
    pk.verify(sig, file);
  } catch (error) {
    if (error.message === 'Weak Public Key') {
      const mem = minizign.getSlice(pk.string);
      const decoder = new TextDecoder();
      console.log(`Weak Public Key: ${decoder.decode(mem.used)}`);
    }
    throw error;
  } finally {
    pk?.deinit();
    sig?.deinit();
  }
}); 

test('invalid public key, valid signature and file', async (t) => { 
  const minizign = new Minizign();

  await minizign.init();
  
  let failed = false;
  let pk = null;
  let sig = null;
  try { 
    pk = minizign.publicKey(publicKeyInvalid);
    sig = minizign.signature(signature);
    pk.verify(sig, file); // Error thrown here
    failed = true; // If try is still executing, it is a problem
  } catch {
    // Do nothing
  } finally {
    pk?.deinit();
    sig?.deinit();
  }
  if (failed) throw new Error('Invalid public key did not throw error');
});


test('signature returns correct type', async (t) => { 
  const minizign = new Minizign();

  await minizign.init();
  
  let sig = null;
  try {
    sig = minizign.signature(signature);
    if (!sig instanceof Signature) {
      throw new Error('Signature is of unknown type');
    }
  } finally {
    sig?.deinit();
  }
}); 

