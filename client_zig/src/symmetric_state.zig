const std = @import("std");
const CipherState = @import("./cipher_state.zig").CipherState;
const Hash = @import("./hash.zig").Hash;

pub const SymmetricState = struct {
    cipher_state: CipherState,
    chaining_key: Hash,
    hash: Hash,

    const Self = @This();

    pub fn init(protocol_name: []const u8) Self {
        const hash = switch (protocol_name.len) {
            0...32 => blk: {
                var h = Hash.empty();
                std.mem.copy(u8, &h.h, protocol_name);
                break :blk h;
            },
            else => Hash.hash(protocol_name),
        };

        return .{
            .cipher_state = CipherState.init(),
            .chaining_key = hash,
            .hash = hash,
        };
    }

    pub fn mixHash(self: *Self, data: []const u8) void {
        self.hash = Hash.hashWithContext(&self.hash.h, data);
    }
};
