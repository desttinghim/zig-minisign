const std = @import("std");
const lib = @import("lib.zig");
const PublicKey = lib.PublicKey;
const Signature = lib.Signature;

const alloc = std.heap.wasm_allocator;

pub const Result = enum(isize) {
    OutOfMemory = -1,
    InvalidEncoding = -2,
    InvalidCharacter = -3,
    InvalidPadding = -4,
    NoSpaceLeft = -5,
    UnsupportedAlgorithm = -6,
    KeyIdMismatch = -7,
    SignatureVerificationFailed = -8,
    NonCanonical = -9,
    IdentityElement = -10,
    WeakPublicKey = -11,
    _,

    comptime {
        const type_info = @typeInfo(Result);
        for (type_info.Enum.fields) |field| {
            if (field.value >= 0) {
                @compileError("Result values must be negative.");
            }
        }
    }

    fn fromPointer(ptr: *anyopaque) Result {
        const int: usize = @intFromPtr(ptr);

        // Assert that the first bit is not set since that would
        // make it a negative value.
        std.debug.assert(@clz(int) >= 1);

        return @enumFromInt(int);
    }
};

/// Allocate a buffer in wasm memory
export fn allocate(len: u32) Result {
    const buf = alloc.alloc(u8, len) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
    };
    return Result.fromPointer(buf.ptr);
}

/// Free a buffer in wasm memory
export fn free(pointer: [*]u8, len: u32) void {
    alloc.free(pointer[0..len]);
}

/// Takes minisign signature and creates a Signature object in memory.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn signatureDecode(str: [*]const u8, len: u32) Result {
    const sig = struct {
        fn impl(str_: [*]const u8, len_: u32) !*Signature {
            const sig: *Signature = try alloc.create(Signature);
            errdefer alloc.destroy(sig);

            sig.* = try Signature.decode(alloc, str_[0..len_]);

            return sig;
        }
    }.impl(str, len) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
        error.InvalidEncoding => return .InvalidEncoding,
        error.InvalidCharacter => return .InvalidCharacter,
        error.InvalidPadding => return .InvalidPadding,
        error.NoSpaceLeft => return .NoSpaceLeft,
    };
    return Result.fromPointer(sig);
}

/// De-initializes a signature object
export fn signatureDeinit(sig: *Signature) void {
    sig.deinit();
}

/// Takes a base64 encoded string and creates a PublicKey object in the provided buffer.
/// On success, returns the number of bytes used. On failure, returns 0.
export fn publicKeyFromBase64(str: [*]const u8, len: u32) Result {
    const pk = struct {
        fn impl(str_: [*]const u8, len_: u32) !*PublicKey {
            const pk: *PublicKey = try alloc.create(PublicKey);
            errdefer alloc.destroy(pk);

            pk.* = try PublicKey.fromBase64(str_[0..len_]);

            return pk;
        }
    }.impl(str, len) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
        error.InvalidEncoding => return .InvalidEncoding,
        error.InvalidCharacter => return .InvalidCharacter,
        error.InvalidPadding => return .InvalidPadding,
        error.NoSpaceLeft => return .NoSpaceLeft,
        error.UnsupportedAlgorithm => return .UnsupportedAlgorithm,
    };

    return Result.fromPointer(pk);
}

/// De-initialize a public key object
export fn publicKeyDeinit(pk: *PublicKey) void {
    alloc.destroy(pk);
}

/// Verifies the integrity of a file with a public key and signature.
/// Returns 1 on success, and a Result error code on failure.
export fn publicKeyVerify(
    pk: *const PublicKey,
    sig: *const Signature,
    file: [*]const u8,
    file_len: u32,
) Result {
    pk.verify(alloc, file[0..file_len], sig.*, null) catch |e| switch (e) {
        error.OutOfMemory => return .OutOfMemory,
        error.InvalidEncoding => return .InvalidEncoding,
        error.UnsupportedAlgorithm => return .UnsupportedAlgorithm,
        error.KeyIdMismatch => return .KeyIdMismatch,
        error.SignatureVerificationFailed => return .SignatureVerificationFailed,
        error.NonCanonical => return .NonCanonical,
        error.IdentityElement => return .IdentityElement,
        error.WeakPublicKey => return .WeakPublicKey,
    };

    return @enumFromInt(1);
}
