const std = @import("std");
const Key = @import("./key.zig").Key;
const Allocator = std.mem.Allocator;

pub const Error = error{
    MaxNonceReached,
};

pub const CipherState = struct {
    key: Key,
    nonce: u64,

    const Self = @This();

    pub fn init(k: Key) Self {
        return .{
            .key = k,
            .nonce = 0,
        };
    }

    pub fn empty() Self {
        return Self.init(Key.empty());
    }

    pub fn isEmpty(self: Self) bool {
        return self.key.isEmpty();
    }

    pub fn encryptWithAd(self: *Self, allocator: Allocator, ad: []const u8, plaintext: []const u8) ![]const u8 {
        if (self.nonce == std.math.maxInt(@TypeOf(self.nonce))) {
            return Error.MaxNonceReached;
        }

        const ciphertext = try self.key.encrypt(allocator, self.nonce, ad, plaintext);
        self.nonce += 1;
        return ciphertext;
    }

    pub fn decryptWithAd(self: *Self, allocator: Allocator, ad: []const u8, ciphertext: []const u8) ![]const u8 {
        if (self.nonce == std.math.maxInt(@TypeOf(self.nonce))) {
            return Error.MaxNonceReached;
        }

        const plaintext = try self.key.decrypt(allocator, self.nonce, ad, ciphertext);
        self.nonce += 1;
        return plaintext;
    }
};
