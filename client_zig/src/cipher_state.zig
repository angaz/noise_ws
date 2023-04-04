const std = @import("std");
const Key = @import("./key.zig").Key32;
const Message = @import("./message.zig").Message;
const Ciphertext = @import("ciphertext.zig").Ciphertext;
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

    pub fn encryptWithAd(self: *Self, allocator: Allocator, ad: []const u8, plaintext: []const u8) !Ciphertext {
        if (self.nonce == std.math.maxInt(@TypeOf(self.nonce))) {
            return Error.MaxNonceReached;
        }

        defer self.nonce += 1;
        return try self.key.encrypt(allocator, self.nonce, ad, plaintext);
    }

    pub fn decryptWithAd(self: *Self, allocator: Allocator, ad: []const u8, ciphertext: Ciphertext) ![]const u8 {
        if (self.nonce == std.math.maxInt(@TypeOf(self.nonce))) {
            return Error.MaxNonceReached;
        }

        defer self.nonce += 1;
        return try self.key.decrypt(allocator, self.nonce, ad, ciphertext);
    }
};
