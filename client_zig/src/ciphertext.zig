const std = @import("std");
const Allocator = std.mem.Allocator;
const Tag16 = @import("tag.zig").Tag16;

pub const Ciphertext = struct {
    tag: Tag16,
    ciphertext: []const u8,

    const Self = @This();
    pub const tag_len = Tag16.len;

    pub fn init(tag: Tag16, ciphertext: []const u8) Self {
        return .{
            .tag = tag,
            .ciphertext = ciphertext,
        };
    }

    pub fn deinit(self: Self, allocator: Allocator) void {
        allocator.free(self.ciphertext);
    }

    pub fn empty() Self {
        return Self.init(Tag16.empty(), []const u8{});
    }

    pub fn len(self: Self) usize {
        return Tag16.len + self.ciphertext.len;
    }

    pub fn writeTo(self: Self, out: []u8) void {
        std.mem.copy(u8, out, &self.tag.tag);
        std.mem.copy(u8, out[Self.tag_len..], self.ciphertext);
    }

    pub fn readFrom(in: []const u8) Self {
        return Self.init(Tag16.copy(in[0..Self.tag_len]), in[Self.tag_len..]);
    }
};
