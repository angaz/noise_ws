const std = @import("std");
const Key = @import("key.zig").Key;
const Ciphertext = @import("ciphertext.zig").Ciphertext;
const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Error = error{
    InvalidBuffer,
};

pub const Message = struct {
    ephemeral: Key,
    static: Key,
    ciphertext: Ciphertext,

    const Self = @This();

    pub fn init(
        ephemeral: Key,
        static: Key,
        ciphertext: Ciphertext,
    ) Self {
        return .{
            .ephemeral = ephemeral,
            .static = static,
            .ciphertext = ciphertext,
        };
    }

    pub fn deinit(self: Self, allocator: Allocator) void {
        self.ciphertext.deinit(allocator);
    }

    pub fn emptyWithCiphertext(ciphertext: Ciphertext) Self {
        return Self.init(
            Key.empty(),
            Key.empty(),
            ciphertext,
        );
    }

    pub fn empty() Self {
        return Self.emptyWithCiphertext(Ciphertext.empty());
    }

    pub fn encodedLength(self: Self) usize {
        return Key.len * 2 + self.ciphertext.len();
    }

    pub fn writeTo(self: Self, out: []u8) void {
        std.mem.copy(u8, out, &self.ephemeral.key);
        std.mem.copy(u8, out[Key.len..], &self.static.key);
        self.ciphertext.writeTo(out[Key.len * 2 ..]);
    }

    pub fn encode(self: Self, allocator: Allocator) ![]const u8 {
        const out = try allocator.alloc(u8, self.encodedLength());
        self.writeTo(out);
        return out;
    }

    pub fn readFrom(in: []const u8) Self {
        return Self.init(
            Key.copy(in[0..Key.len]),
            Key.copy(in[Key.len .. Key.len * 2]),
            Ciphertext.readFrom(in[Key.len * 2 ..]),
        );
    }

    pub fn decode(in: []const u8) Error!Self {
        return Self.readFrom(in);
    }
};
