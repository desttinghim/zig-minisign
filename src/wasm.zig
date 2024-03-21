const std = @import("std");
const lib = @import("lib.zig");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;

export fn allocateBuffer(len: u32) ?[*]u8 {
    const alloc = std.heap.wasm_allocator;
    const buf = alloc.alloc(u8, len) catch return null;
    return buf.ptr;
}

/// Takes a base64 encoded string and creates a PublicKey object in the provided buffer.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn publicKeyFromBase64(str: [*]const u8, len: u32) ?*PublicKey {
    const alloc = std.heap.wasm_allocator;
    const pk: *PublicKey = alloc.create(PublicKey) catch return null;
    errdefer alloc.destroy(pk);

    pk.* = PublicKey.fromBase64(str[0..len]) catch return null;

    return pk;
}

/// Takes minisign signature and creates a Signature object in memory.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn signatureDecode(str: [*]const u8, len: u32) ?*Signature {
    const alloc = std.heap.wasm_allocator;
    const sig: *Signature = alloc.create(Signature) catch return null;
    errdefer alloc.destroy(sig);

    sig.* = Signature.decode(alloc, str[0..len]) catch return null;

    return sig;
}

/// Takes a pointer to a PublicKey, a pointer to a Signature
export fn publicKeyVerifySignature(
    pk: *const PublicKey,
    sig: *const Signature,
    file: [*]const u8,
    file_len: u32,
) bool {
    const alloc = std.heap.wasm_allocator;

    pk.verify(alloc, file[0..file_len], sig.*, null) catch return false;

    return true;
}
