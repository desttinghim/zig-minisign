const std = @import("std");
const lib = @import("lib.zig");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;

/// Takes a base64 encoded string and creates a PublicKey object in the provided buffer.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn publicKeyFromBase64(str: [*]const u8, len: u32, buffer: [*]u8, buffer_length: u32) u32 {
    if (buffer_length < @sizeOf(PublicKey)) return 0;
    const pk: *PublicKey = @alignCast(@ptrCast(buffer));

    pk.* = PublicKey.fromBase64(str[0..len]) catch return 0;

    return @sizeOf(PublicKey);
}

/// Takes minisign signature and creates a Signature object in memory.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn signatureDecode(str: [*]const u8, len: u32, buffer: [*]u8, buffer_length: u32) u32 {
    if (buffer_length < @sizeOf(Signature)) return 0;
    const sig: *Signature = @alignCast(@ptrCast(buffer));

    var fba = std.heap.FixedBufferAllocator.init(buffer[@sizeOf(Signature)..buffer_length]);

    sig.* = Signature.decode(fba.allocator(), str[0..len]) catch return 0;

    return @sizeOf(Signature) + fba.end_index;
}

/// Takes a pointer to a PublicKey, a pointer to a Signature
export fn publicKeyVerifySignature(
    pk: *const PublicKey,
    sig: *const Signature,
    file: [*]const u8,
    file_len: u32,
    buffer: [*]u8,
    buffer_length: u32,
) u32 {
    var fba = std.heap.FixedBufferAllocator.init(buffer[0..buffer_length]);

    pk.verify(fba.allocator(), file[0..file_len], sig.*, null) catch return 0;

    return fba.end_index;
}
