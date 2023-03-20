const std = @import("std");
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

fn initBlake2s() Blake2s256 {
    return Blake2s256.init(.{
        .expected_out_bits = 256,
    });
}

pub const Hash = struct {
    hash: [HASH_LEN]u8 = undefined,

    const Self = @This();
    pub const HASH_LEN = 32;

    pub fn init(h: [HASH_LEN]u8) Self {
        return .{
            .hash = h,
        };
    }

    pub fn empty() Self {
        return Self.init(std.mem.zeroes([HASH_LEN]u8));
    }

    pub fn hash(data: []const u8) Self {
        var context = initBlake2s();
        context.update(data);

        var h = Self.empty();
        context.final(h.hash);

        return h;
    }

    pub fn hashWithContext(previous: []const u8, data: []const u8) Self {
        var context = initBlake2s();
        context.update(previous);
        context.update(data);

        var h = Self.empty();
        context.final(h.hash);

        return h;
    }
};
