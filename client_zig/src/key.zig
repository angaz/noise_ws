const std = @import("std");
const Message = @import("./message.zig").Message;
const fillRandom = @import("./random.zig").fillRandom;
const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Key = struct {
    key: [Self.len]u8,

    pub const len = 32;
    const Self = @This();

    pub fn init(key: [Self.len]u8) Self {
        return .{
            .key = key,
        };
    }

    pub fn empty() Self {
        return Self.init(std.mem.zeroes([Self.len]u8));
    }

    /// TODO: Yeah it's not really constant time, but I tried.
    pub fn isEmpty(self: Self) bool {
        var v: u8 = 0;
        for (self.key) |c| {
            v |= c;
        }

        return v == 0;
    }

    pub fn copy(data: *const [Self.len]u8) Self {
        var out = Self.empty();
        std.mem.copy(u8, &out.key, data);
        return out;
    }

    pub fn genPrivateKey() Self {
        var new = Self.empty();
        fillRandom(&new.key);
        return new;
    }

    pub fn genPublicKey(self: Self) !Self {
        return Self.init(try std.crypto.dh.X25519.recoverPublicKey(self.key));
    }

    pub fn dh(self: Self, public: Self) ![Self.len]u8 {
        return try std.crypto.dh.X25519.scalarmult(self.key, public.key);
    }

    pub fn encrypt(self: Self, allocator: Allocator, nonce: u64, ad: []const u8, plaintext: []const u8) !Message {
        var ciphertext = try allocator.alloc(u8, plaintext.len);
        var npub = std.mem.zeroes([ChaCha20Poly1305.nonce_length]u8);
        std.mem.writeIntSliceLittle(u64, &npub, nonce);

        var message = Message.empty();

        ChaCha20Poly1305.encrypt(
            ciphertext,
            &message.tag,
            plaintext,
            ad,
            npub,
            self.key,
        );

        message.ciphertext = ciphertext;
        return message;
    }

    pub fn decrypt(self: Self, allocator: Allocator, nonce: u64, ad: []const u8, message: Message) ![]const u8 {
        var plaintext = try allocator.alloc(u8, message.ciphertext.len);
        var npub = std.mem.zeroes([ChaCha20Poly1305.nonce_length]u8);
        std.mem.writeIntSliceLittle(u64, &npub, nonce);

        try ChaCha20Poly1305.decrypt(
            plaintext,
            message.ciphertext,
            message.tag,
            ad,
            npub,
            self.key,
        );

        return plaintext;
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

    pub fn dh(self: Self, public: Key) !Key {
        return Key.init(try self.private.dh(public));
    }
};
