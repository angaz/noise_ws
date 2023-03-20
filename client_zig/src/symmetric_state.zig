const std = @import("std");
const CipherState = @import("./cipher_state.zig").CipherState;
const Hash = @import("./hash.zig").Hash;

pub const SymmetricState = struct {
    cipher_state: CipherState = undefined,
    chaining_key: Hash = undefined,
    hash: Hash = undefined,

    const Self = @This();

    pub fn init(protocolName: []const u8) Self {
        const hash = switch (protocolName.len) {
            0...31 => blk: {
                var h = Hash.empty();
                std.mem.copy(u8, h.hash, protocolName);
                break :blk h;
            },
            32 => Hash.init(protocolName),
            else => Hash.hash(protocolName),
        };

        return .{
            .cipher_state = CipherState.init(),
            .chaining_key = hash,
            .hash = hash,
        };
    }

    pub fn mixHash(self: *Self, data: []const u8) void {
        self.hash = Hash.hashWithContext(self.hash.hash, data);
    }
};
