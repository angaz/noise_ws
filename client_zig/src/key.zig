const std = @import("std");
const Allocator = std.mem.Allocator;

pub const KEY_LEN = 32;

pub const Key = struct {
    key: [KEY_LEN]u8 = undefined,

    const Self = @This();

    pub fn init(allocator: Allocator, key: [KEY_LEN]u8) !Self {
        return .{
            .key = try allocator.dupe(u8, key),
        };
    }

    /// Generates a public key, given self is a private key.
    pub fn genPubkey(self: *Self, allocator: Allocator) !Self {
        return .{
            .key = try allocator.dupe(u8, self.key),
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

    pub fn init(allocator: Allocator, private: Key) Self {
        return .{
            .private = private,
            .public = private.genPubkey(allocator),
        };
    }
};
