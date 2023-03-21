const std = @import("std");
const Allocator = std.mem.Allocator;

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

    pub fn copy(data: *[key_len]u8) Self {
        var out = Self.empty();
        std.mem.copy(u8, &out.key, data);
        return out;
    }

    /// Generates a public key, given self is a private key.
    pub fn genPubkey(self: Self) !Self {
        return .{
            .key = try std.crypto.dh.X25519.recoverPublicKey(self.key),
        };
    }
};

pub const Keypair = struct {
    private: Key,
    public: Key,

    const Self = @This();

    pub fn init(private: Key) !Self {
        return .{
            .private = private,
            .public = try private.genPubkey(),
        };
    }

    pub fn empty() Self {
        return .{
            .private = Key.empty(),
            .public = Key.empty(),
        };
    }
};
