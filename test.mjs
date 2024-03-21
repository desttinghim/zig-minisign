import fs from 'node:fs/promises';
import test from 'node:test'

import Minizign from './minizign.mjs';

const minizign = new Minizign();
  
const publicKey = 'RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U';
const publicKeyInvalid = 'RWSGOq2NVecA2UPNiBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U';
const signature = await fs.readFile('zig-linux-x86_64-0.12.0-dev.3180+83e578a18.tar.xz.minisig');
const file = await fs.readFile('zig-linux-x86_64-0.12.0-dev.3180+83e578a18.tar.xz');

test('valid public key, signature, and file', async (t) => { 
  await minizign.verify(publicKey, signature, file);
}); 

test('invalid public key, valid signature and file', async (t) => { 
  let failed = false;
  try { 
    await minizign.verify(publicKeyInvalid, signature, file);   
    failed = true;
  }  catch {}
  if (failed) throw new Error('Invalid public key did not throw error');
});

