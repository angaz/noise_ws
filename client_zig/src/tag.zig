const std = @import("std");

pub const Tag16 = Tag(16);

pub fn Tag(comptime length: usize) type {
    return struct {
        tag: [Self.len]u8,

        const Self = @This();
        pub const len = length;

        pub fn empty() Self {
            return .{
                .tag = std.mem.zeroes([Self.len]u8),
            };
        }

        pub fn init(tag: [Self.len]u8) Self {
            return .{
                .tag = tag,
            };
        }

        pub fn copy(data: []const u8) Self {
            var tag = Self.empty();
            std.mem.copy(u8, &tag.tag, data);
            return tag;
        }
    };
}
