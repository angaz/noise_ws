const std = @import("std");
const Key = @import("key.zig").Key;
const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Error = error{
    InvalidBuffer,
};

pub const Message = struct {
    ephemeral: Key,
    static: Key,
    tag: [Self.tag_len]u8,
    ciphertext: []const u8,

    const Self = @This();
    const tag_len = ChaCha20Poly1305.tag_length;
    const bufferSizeWithoutCiphertext = Key.len * 2 + Self.tag_len;

    pub fn emptyWithCiphertext(ciphertext: []const u8) Self {
        return .{
            .ephemeral = Key.empty(),
            .static = Key.empty(),
            .tag = std.mem.zeroes([Self.tag_len]u8),
            .ciphertext = ciphertext,
        };
    }

    pub fn empty() Self {
        return Self.emptyWithCiphertext("");
    }

    pub fn encodedLength(self: Self) usize {
        return Self.bufferSizeWithoutCiphertext + self.ciphertext.len;
    }

    pub fn writeTo(self: Self, out: []u8) void {
        std.mem.copy(u8, out, &self.ephemeral.key);
        std.mem.copy(u8, out[Key.len..], &self.static.key);
        std.mem.copy(u8, out[Key.len * 2 ..], &self.tag);
        std.mem.copy(u8, out[Key.len * 2 + Self.tag_len ..], self.ciphertext);
    }

    pub fn encode(self: Self, allocator: Allocator) ![]const u8 {
        const out = try allocator.alloc(u8, self.encodedLength());
        self.writeTo(out);
        return out;
    }

    pub fn readFrom(in: []const u8) Error!Self {
        if (in.len < Self.bufferSizeWithoutCiphertext) {
            return Error.InvalidBuffer;
        }

        return .{
            .ephemeral = in[0..Key.len],
            .static = in[Key.len .. Key.len * 2],
            .tag = in[Key.len * 2 .. Key.len * 2 + Self.tag_len],
            .ciphertext = in[Key.len * 2 + Self.tag_len ..],
        };
    }
};
