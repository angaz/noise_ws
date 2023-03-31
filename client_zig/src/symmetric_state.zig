const std = @import("std");
const CipherState = @import("./cipher_state.zig").CipherState;
const Hash = @import("./hash.zig").Hash;
const Key = @import("./key.zig").Key;
const Message = @import("./message.zig").Message;
const Ciphertext = @import("ciphertext.zig").Ciphertext;
const Tag16 = @import("tag.zig").Tag16;
const Allocator = std.mem.Allocator;
const Hkdf = std.crypto.kdf.hkdf.Hkdf(
    std.crypto.auth.hmac.Hmac(
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

    fn hkdf(self: *Self, ikm: Key, comptime n_keys: usize) [n_keys * Key.len]u8 {
        var out = std.mem.zeroes([n_keys * Key.len]u8);
        const prk = Hkdf.extract(&self.chaining_key.hash, &ikm.key);
        Hkdf.expand(&out, "", prk);

        return out;
    }

    pub fn mixKey(self: *Self, ikm: Key) void {
        const out = self.hkdf(ikm, 2);
        self.chaining_key = Hash.init(out[0..Key.len].*);
        self.cipher_state = CipherState.init(Key.init(out[Key.len..].*));
    }

    pub fn mixKeyAndHash(self: *Self, ikm: Key) void {
        const h1 = Hash.len;
        const h2 = h1 * 2;

        const out = self.hkdf(ikm, 3);
        self.chaining_key = Hash.init(out[0..h1].*);
        self.mixHash(out[h1..h2]);
        self.cipher_state = CipherState.init(Key.init(out[h2..].*));
    }

    pub fn encryptAndHash(self: *Self, allocator: Allocator, plaintext: []const u8) !Ciphertext {
        const ciphertext = if (self.cipher_state.isEmpty())
            Ciphertext.init(Tag16.empty(), try allocator.dupe(u8, plaintext))
        else
            try self.cipher_state.encryptWithAd(allocator, &self.hash.hash, plaintext);

        self.mixHash(ciphertext.ciphertext);
        return ciphertext;
    }

    pub fn decryptAndHash(self: *Self, allocator: Allocator, ciphertext: Ciphertext) ![]const u8 {
        const plaintext = if (self.cipher_state.isEmpty())
            try allocator.dupe(u8, ciphertext.ciphertext)
        else
            try self.cipher_state.decryptWithAd(allocator, &self.hash.hash, ciphertext);

        self.mixHash(ciphertext.ciphertext);
        return plaintext;
    }

    pub fn split(self: *Self, cs1: *CipherState, cs2: *CipherState) void {
        const out = self.hkdf(Key.empty(), 2);

        cs1.key = Key.init(out[0..Key.len].*);
        cs2.key = Key.init(out[Key.len..].*);
    }
};
