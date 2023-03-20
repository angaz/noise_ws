const std = @import("std");
const Allocator = std.mem.Allocator;

pub const KEY_LEN = 32;

pub const Key = struct {
    key: [KEY_LEN]u8 = undefined,

    const Self = @This();

    pub fn init(key: [KEY_LEN]u8) Self {
        return .{
            .key = key,
        };
    }

    pub fn empty() Self {
        return Self.init(std.mem.zeroes([KEY_LEN]u8));
    }

    /// Generates a public key, given self is a private key.
    pub fn genPubkey(self: *Self) !Self {
        return .{
            .key = std.crypto.dh.X25519.recoverPublicKey(self.key),
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.free(self.key);
    }
};

pub const Keypair = struct {
    private: Key = undefined,
    public: Key = undefined,

    const Self = @This();

    pub fn init(private: Key) Self {
        return .{
            .private = private,
            .public = private.genPubkey(),
        };
    }
};
