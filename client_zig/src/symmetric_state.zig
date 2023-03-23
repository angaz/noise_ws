const std = @import("std");
const CipherState = @import("./cipher_state.zig").CipherState;
const Hash = @import("./hash.zig").Hash;
const key = @import("./key.zig");
const Allocator = std.mem.Allocator;
const Key = key.Key;
const Hkdf = std.crypto.kdf.hkdf.Hkdf(
    std.crypto.kdf.hkdf.hmac.Hmac(
        std.crypto.hash.blake2.Blake2s256,
    ),
);

pub const SymmetricState = struct {
    cipher_state: CipherState,
    chaining_key: Hash,
    hash: Hash,

    const Self = @This();

    pub fn init(protocol_name: []const u8) Self {
        const hash = switch (protocol_name.len) {
            0...32 => blk: {
                var h = Hash.empty();
                std.mem.copy(u8, &h.hash, protocol_name);
                break :blk h;
            },
            else => Hash.hash(protocol_name),
        };

        return .{
            .cipher_state = CipherState.empty(),
            .chaining_key = hash,
            .hash = hash,
        };
    }

    pub fn mixHash(self: *Self, data: []const u8) void {
        self.hash = Hash.hashWithContext(&self.hash.hash, data);
    }

    pub fn mixKey(self: *Self, ikm: Key) void {
        var out = std.mem.zeroes([Hash.hash_len * 2]u8);

        const prk = Hkdf.extract(self.chaining_key.hash, ikm);
        Hkdf.expand(out, [_]u8{}, prk);

        self.chaining_key.hash = out[0..Hash.hash_len];
        self.cipher_state = CipherState.init(Key.init(out[Hash.hash_len..]));
    }

    pub fn mixKeyAndHash(self: *Self, ikm: Key)

    pub fn encryptAndHash(self: *Self, allocator: Allocator, plaintext: []const u8) ![]const u8 {
        const ciphertext = if (self.cipher_state.isEmpty())
            try allocator.dupe(u8, plaintext)
        else
            try self.cipher_state.encryptWithAd(allocator, self.hash.hash, plaintext);

        self.mixHash(ciphertext);
        return ciphertext;
    }

    pub fn decryptAndHash(self: *Self, allocator: Allocator, ciphertext: []const u8) ![]const u8 {
        const plaintext = if (self.cipher_state.isEmpty())
            try allocator.dupe(u8, ciphertext)
        else
            try self.cipher_state.decryptWithAd(allocator, self.hash.hash, ciphertext);

        self.mixHash(ciphertext);
        return plaintext;
    }
};
