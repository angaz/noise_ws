const std = @import("std");
const Key = @import("./key.zig").Key;
const Message = @import("./message.zig").Message;
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

    pub fn encryptWithAd(self: *Self, allocator: Allocator, ad: []const u8, plaintext: []const u8) !Message {
        if (self.nonce == std.math.maxInt(@TypeOf(self.nonce))) {
            return Error.MaxNonceReached;
        }

        const message = try self.key.encrypt(allocator, self.nonce, ad, plaintext);
        self.nonce += 1;
        return message;
    }

    pub fn decryptWithAd(self: *Self, allocator: Allocator, ad: []const u8, message: Message) ![]const u8 {
        if (self.nonce == std.math.maxInt(@TypeOf(self.nonce))) {
            return Error.MaxNonceReached;
        }

        const plaintext = try self.key.decrypt(allocator, self.nonce, ad, message);
        self.nonce += 1;
        return plaintext;
    }
};
