const std = @import("std");
const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const key_len = 32;

pub const Key = struct {
    key: [key_len]u8,

    const Self = @This();

    pub fn init(key: [key_len]u8) Self {
        return .{
            .key = key,
        };
    }

    pub fn empty() Self {
        return Self.init(std.mem.zeroes([key_len]u8));
    }

    /// TODO: Yeah it's not really constant time, but I tried.
    pub fn isEmpty(self: Self) bool {
        var v: u8 = 0;
        for (self.key) |c| {
            v |= c;
        }

        return v == 0;
    }

    pub fn copy(data: *[key_len]u8) Self {
        var out = Self.empty();
        std.mem.copy(u8, &out.key, data);
        return out;
    }

    pub fn genPrivateKey() Self {
        var new = Self.empty();
        std.crypto.random.bytes(&new.key);
        return new;
    }

    pub fn genPublicKey(self: Self) !Self {
        return Self.init(try std.crypto.dh.X25519.recoverPublicKey(self.key));
    }

    pub fn dh(self: Self, public: Self) ![key_len]u8 {
        return try std.crypto.dh.X25519.scalarmult(self.key, public.key);
    }

    pub fn encrypt(self: Self, allocator: Allocator, nonce: u64, ad: []const u8, plaintext: []const u8) ![]const u8 {
        var ciphertext = allocator.alloc(u8, plaintext.len + ChaCha20Poly1305.tag_length);
        var npub = std.mem.zeroes([ChaCha20Poly1305.nonce_length]u8);
        std.mem.writeIntSliceLittle(u64, &npub, nonce);

        try ChaCha20Poly1305.encrypt(
            ciphertext[0..plaintext.len],
            ciphertext[plaintext.len..],
            plaintext,
            ad,
            npub,
            self.key,
        );

        return ciphertext;
    }
    pub fn decrypt(self: Self, allocator: Allocator, nonce: u64, ad: []const u8, ciphertext: []const u8) ![]const u8 {
        var plaintext = allocator.alloc(u8, ciphertext.len - ChaCha20Poly1305.tag_length);
        var npub = std.mem.zeroes([ChaCha20Poly1305.nonce_length]u8);
        std.mem.writeIntSliceLittle(u64, &npub, nonce);

        try ChaCha20Poly1305.decrypt(
            plaintext,
            ciphertext[0..plaintext.len],
            ciphertext[plaintext.len..],
            ad,
            npub,
            self.key,
        );

        return ciphertext;
    }
};

pub const Keypair = struct {
    private: Key,
    public: Key,

    const Self = @This();

    pub fn init(private: Key) !Self {
        return .{
            .private = private,
            .public = try private.genPublicKey(),
        };
    }

    pub fn empty() Self {
        return .{
            .private = Key.empty(),
            .public = Key.empty(),
        };
    }

    pub fn genKeypair() !Self {
        return try Self.init(Key.genPrivateKey());
    }

    pub fn dh(self: Self, public: Key) ![key_len]u8 {
        return try self.private.dh(public);
    }
};
