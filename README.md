# minizign

Fork of [zig-minisign](https://github.com/jedisct1/zig-minisign) that provides a JS interface to verify minisign signatures.

## Example

```js
import 'node:fs/promises'
import { Minizign } from 'minizign'

const minizign = new Minizign()

await minizign.init() // Init must be run to initialize the wasm module

const publicKey = '...' // Base64 encoded public key
const file = await fs.readFile('file')
const signature = await fs.readFile('file.minisig')

const pk = minizign.publicKey(publicKey)
const sig = minizign.signature(signature)

// If the signature fails to verify, an exception will be thrown
pk.verify(sig, file) 

// this next part is only needed if minizign will be reused
pk.deinit()
sig.deinit()
```

## Compilation

### Wasm modules

Requires the current `master` version of [Zig](https://ziglang.org).
 
```sh
zig build -Doptimize=ReleaseFast -Dupdate-module
```

### Javascript

```sh
npm install
npm build
npm test
````

