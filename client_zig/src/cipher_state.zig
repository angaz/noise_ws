const std = @import("std");
const Key = @import("./key.zig").Key;

pub const CipherState = struct {
    key: Key,
    nonce: u64,

    const Self = @This();

    pub fn init() Self {
        return .{
            .key = Key.empty(),
            .nonce = 0,
        };
    }
};
