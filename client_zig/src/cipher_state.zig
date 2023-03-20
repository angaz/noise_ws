const std = @import("std");
const key = @import("./key.zig");
const nonce = @import("./nonce.zig");
const Key = key.Key;
const Nonce = nonce.Nonce;

pub const CipherState = struct {
    key: Key,
    nonce: Nonce,

    const Self = @This();

    pub fn init() Self {
        return .{
            .key = Key.empty(),
            .nonce = Nonce.init(),
        };
    }
};
