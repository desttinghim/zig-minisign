const std = @import("std");
const base64 = std.base64;
const crypto = std.crypto;
const debug = std.debug;
const fs = std.fs;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const math = std.math;
const mem = std.mem;
const os = std.os;
const process = std.process;
const Blake2b512 = crypto.hash.blake2.Blake2b512;
const Ed25519 = crypto.sign.Ed25519;
const Endian = std.builtin.Endian;

pub const Signature = struct {
    arena: heap.ArenaAllocator,
    untrusted_comment: []u8,
    signature_algorithm: [2]u8,
    key_id: [8]u8,
    signature: [64]u8,
    trusted_comment: []u8,
    global_signature: [64]u8,

    pub fn deinit(self: *Signature) void {
        self.arena.deinit();
    }

    pub fn decode(child_allocator: mem.Allocator, lines_str: []const u8) !Signature {
        var arena = heap.ArenaAllocator.init(child_allocator);
        errdefer arena.deinit();
        var it = mem.tokenize(u8, lines_str, "\n");
        const untrusted_comment = it.next() orelse return error.InvalidEncoding;
        var bin1: [74]u8 = undefined;
        try base64.standard.Decoder.decode(&bin1, it.next() orelse return error.InvalidEncoding);
        var trusted_comment = it.next() orelse return error.InvalidEncoding;
        if (!mem.startsWith(u8, trusted_comment, "trusted comment: ")) {
            return error.InvalidEncoding;
        }
        trusted_comment = trusted_comment["Trusted comment: ".len..];
        var bin2: [64]u8 = undefined;
        try base64.standard.Decoder.decode(&bin2, it.next() orelse return error.InvalidEncoding);
        const sig = Signature{
            .arena = arena,
            .untrusted_comment = try arena.allocator().dupe(u8, untrusted_comment),
            .signature_algorithm = bin1[0..2].*,
            .key_id = bin1[2..10].*,
            .signature = bin1[10..74].*,
            .trusted_comment = try arena.allocator().dupe(u8, trusted_comment),
            .global_signature = bin2,
        };
        return sig;
    }

    pub fn fromFile(allocator: mem.Allocator, path: []const u8) !Signature {
        const fd = try fs.cwd().openFile(path, .{ .mode = .read_only });
        defer fd.close();
        const sig_str = try fd.readToEndAlloc(allocator, 4096);
        defer allocator.free(sig_str);
        return Signature.decode(allocator, sig_str);
    }
};

pub const PublicKey = struct {
    untrusted_comment: ?[]u8 = null,
    signature_algorithm: [2]u8 = "Ed".*,
    key_id: [8]u8,
    key: [32]u8,

    pub fn fromBase64(str: []const u8) !PublicKey {
        if (str.len != 56) {
            return error.InvalidEncoding;
        }
        var bin: [42]u8 = undefined;
        try base64.standard.Decoder.decode(&bin, str);
        const signature_algorithm = bin[0..2];
        if (bin[0] != 0x45 or (bin[1] != 0x64 and bin[1] != 0x44)) {
            return error.UnsupportedAlgorithm;
        }
        const pk = PublicKey{
            .signature_algorithm = signature_algorithm.*,
            .key_id = bin[2..10].*,
            .key = bin[10..42].*,
        };
        return pk;
    }

    pub fn decodeFromSsh(pks: []PublicKey, lines: []const u8) ![]PublicKey {
        var lines_it = mem.tokenize(u8, lines, "\n");
        var i: usize = 0;
        while (lines_it.next()) |line| {
            var pk = PublicKey{ .key_id = mem.zeroes([8]u8), .key = undefined };
            const key_type = "ssh-ed25519";

            var it = mem.tokenize(u8, line, " ");
            const header = it.next() orelse return error.InvalidEncoding;
            if (!mem.eql(u8, key_type, header)) {
                return error.InvalidEncoding;
            }
            const encoded_ssh_key = it.next() orelse return error.InvalidEncoding;
            const pk_len = pk.key.len;
            var ssh_key: [4 + key_type.len + 4 + pk_len]u8 = undefined;
            try base64.standard.Decoder.decode(&ssh_key, encoded_ssh_key);
            if (mem.readInt(u32, ssh_key[0..4], Endian.big) != key_type.len or
                !mem.eql(u8, ssh_key[4..][0..key_type.len], key_type) or
                mem.readInt(u32, ssh_key[4 + key_type.len ..][0..4], Endian.big) != pk.key.len)
            {
                return error.InvalidEncoding;
            }
            mem.copyForwards(u8, &pk.key, ssh_key[4 + key_type.len + 4 ..]);

            const rest = mem.trim(u8, it.rest(), " \t\r\n");
            const key_id_prefix = "minisign key ";
            if (mem.startsWith(u8, rest, key_id_prefix) and rest.len > key_id_prefix.len) {
                mem.writeInt(u64, &pk.key_id, try fmt.parseInt(u64, rest[key_id_prefix.len..], 16), Endian.little);
            }
            pks[i] = pk;
            i += 1;
            if (i == pks.len) break;
        }
        if (i == 0) {
            return error.InvalidEncoding;
        }
        return pks[0..i];
    }

    pub fn decode(pks: []PublicKey, lines_str: []const u8) ![]PublicKey {
        if (decodeFromSsh(pks, lines_str)) |pks_| return pks_ else |_| {}

        var it = mem.tokenize(u8, lines_str, "\n");
        _ = it.next() orelse return error.InvalidEncoding;
        const pk = try fromBase64(it.next() orelse return error.InvalidEncoding);
        pks[0] = pk;
        return pks[0..1];
    }

    pub fn fromFile(allocator: mem.Allocator, pks: []PublicKey, path: []const u8) ![]PublicKey {
        const fd = try fs.cwd().openFile(path, .{ .mode = .read_only });
        defer fd.close();
        const pk_str = try fd.readToEndAlloc(allocator, 4096);
        defer allocator.free(pk_str);
        return PublicKey.decode(pks, pk_str);
    }

    pub fn verify(self: PublicKey, allocator: std.mem.Allocator, file: []const u8, sig: Signature, prehash: ?bool) !void {
        const key_id_len = self.key_id.len;
        const null_key_id = mem.zeroes([key_id_len]u8);
        if (!mem.eql(u8, &null_key_id, &self.key_id) and !mem.eql(u8, &sig.key_id, &self.key_id)) {
            return error.KeyIdMismatch;
        }
        const signature_algorithm = sig.signature_algorithm;
        const prehashed = if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x64) false else if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x44) true else return error.UnsupportedAlgorithm;
        if (prehash) |want_prehashed| {
            if (prehashed != want_prehashed) {
                return error.SignatureVerificationFailed;
            }
        }
        var digest: [64]u8 = undefined;
        const ed25519_pk = try Ed25519.PublicKey.fromBytes(self.key);
        if (prehashed) {
            var h = Blake2b512.init(.{});
            h.update(file);
            h.final(&digest);
            try Ed25519.Signature.fromBytes(sig.signature).verify(&digest, ed25519_pk);
        } else {
            try Ed25519.Signature.fromBytes(sig.signature).verify(file, ed25519_pk);
        }
        var global = try allocator.alloc(u8, sig.signature.len + sig.trusted_comment.len);
        defer allocator.free(global);
        mem.copyForwards(u8, global[0..sig.signature.len], sig.signature[0..]);
        mem.copyForwards(u8, global[sig.signature.len..], sig.trusted_comment);
        try Ed25519.Signature.fromBytes(sig.global_signature).verify(global, ed25519_pk);
    }

    pub fn verifyFile(self: PublicKey, allocator: mem.Allocator, fd: fs.File, sig: Signature, prehash: ?bool) !void {
        const key_id_len = self.key_id.len;
        const null_key_id = mem.zeroes([key_id_len]u8);
        if (!mem.eql(u8, &null_key_id, &self.key_id) and !mem.eql(u8, &sig.key_id, &self.key_id)) {
            std.debug.print("Signature was made using a different key\n", .{});
            return error.KeyIdMismatch;
        }
        const signature_algorithm = sig.signature_algorithm;
        const prehashed = if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x64) false else if (signature_algorithm[0] == 0x45 and signature_algorithm[1] == 0x44) true else return error.UnsupportedAlgorithm;
        if (prehash) |want_prehashed| {
            if (prehashed != want_prehashed) {
                return error.SignatureVerificationFailed;
            }
        }
        var digest: [64]u8 = undefined;
        const ed25519_pk = try Ed25519.PublicKey.fromBytes(self.key);
        if (prehashed) {
            var h = Blake2b512.init(.{});
            var buf: [mem.page_size]u8 = undefined;
            while (true) {
                const read_nb = try fd.read(&buf);
                if (read_nb == 0) {
                    break;
                }
                h.update(buf[0..read_nb]);
            }
            h.final(&digest);
            try Ed25519.Signature.fromBytes(sig.signature).verify(&digest, ed25519_pk);
        } else {
            const buf = try fd.readToEndAlloc(allocator, math.maxInt(usize));
            defer allocator.free(buf);
            try Ed25519.Signature.fromBytes(sig.signature).verify(buf, ed25519_pk);
        }
        var global = try allocator.alloc(u8, sig.signature.len + sig.trusted_comment.len);
        defer allocator.free(global);
        mem.copyForwards(u8, global[0..sig.signature.len], sig.signature[0..]);
        mem.copyForwards(u8, global[sig.signature.len..], sig.trusted_comment);
        try Ed25519.Signature.fromBytes(sig.global_signature).verify(global, ed25519_pk);
    }
};
