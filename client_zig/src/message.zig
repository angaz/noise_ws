const std = @import("std");
const Key32 = @import("key.zig").Key32;
const Ciphertext = @import("ciphertext.zig").Ciphertext;
const Allocator = std.mem.Allocator;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Error = error{
    InvalidBuffer,
};

pub const MessageType = enum(u8) {
    invalid = 0,
    handshake_initiation = 1,
    handshake_response = 2,
    data = 3,
};

pub const MessageHandshake = struct {
    message_type: MessageType,
    ephemeral: Key32,
    ciphertext: Ciphertext,

    const Self = @This();

    pub fn encode(self: Self, allocator: Allocator) ![]const u8 {
        var encoded = try allocator.alloc(u8, @sizeOf(MessageType) + Key32.len + self.ciphertext.len());
        self.writeTo(encoded);
        return encoded;
    }

    pub fn writeTo(self: Self, out: []u8) void {
        std.mem.writeIntSliceLittle(u8, out, @enumToInt(self.message_type));
        std.mem.copy(u8, out[1..], &self.ephemeral.key);
        self.ciphertext.writeTo(out[1 + Key32.len ..]);
    }

    pub fn readFrom(in: []const u8) Self {
        var message_type = @intToEnum(MessageType, std.mem.readIntSliceLittle(u8, in));
        var ephemeral = Key32.copy(in[1 .. Key32.len + 1]);
        var ciphertext = Ciphertext.readFrom(in[1 + Key32.len + 1 ..]);

        return .{
            .message_type = message_type,
            .ephemeral = ephemeral,
            .ciphertext = ciphertext,
        };
    }
};

pub const MessageData = struct {
    message_type: MessageType,
    ciphertext: Ciphertext,

    const Self = @This();

    pub fn encode(self: Self, allocator: Allocator) ![]const u8 {
        var encoded = try allocator.alloc(u8, @sizeOf(MessageType) + self.ciphertext.len());
        self.writeTo(encoded);
        return encoded;
    }

    pub fn writeTo(self: Self, out: []u8) void {
        std.mem.writeIntSliceLittle(u8, out, @enumToInt(self.message_type));
        self.ciphertext.writeTo(out[1..]);
    }

    pub fn readFrom(in: []const u8) Self {
        var message_type = @intToEnum(MessageType, std.mem.readIntSliceLittle(u8, in));
        var ciphertext = Ciphertext.readFrom(in[1..]);

        return .{
            .message_type = message_type,
            .ciphertext = ciphertext,
        };
    }
};

pub const MessageDoNotUse = struct {
    ephemeral: Key32,
    ciphertext: Ciphertext,

    const Self = @This();

    pub fn init(
        ephemeral: Key32,
        ciphertext: Ciphertext,
    ) Self {
        return .{
            .ephemeral = ephemeral,
            .ciphertext = ciphertext,
        };
    }

    pub fn deinit(self: Self, allocator: Allocator) void {
        self.ciphertext.deinit(allocator);
    }

    pub fn emptyWithCiphertext(ciphertext: Ciphertext) Self {
        return Self.init(
            Key32.empty(),
            ciphertext,
        );
    }

    pub fn empty() Self {
        return Self.emptyWithCiphertext(Ciphertext.empty());
    }

    pub fn encodedLength(self: Self) usize {
        return Key32.len + self.ciphertext.len();
    }

    pub fn writeTo(self: Self, out: []u8) void {
        std.mem.copy(u8, out, &self.ephemeral.key);
        self.ciphertext.writeTo(out[Key32.len..]);
    }

    pub fn encode(self: Self, allocator: Allocator) ![]const u8 {
        const out = try allocator.alloc(u8, self.encodedLength());
        self.writeTo(out);
        return out;
    }

    pub fn readFrom(in: []const u8) Self {
        return Self.init(
            Key32.copy(in[0..Key32.len]),
            Ciphertext.readFrom(in[Key32.len..]),
        );
    }

    pub fn decode(in: []const u8) Error!Self {
        return Self.readFrom(in);
    }
};
