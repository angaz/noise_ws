const std = @import("std");
const key = @import("key.zig");

pub const Error = error{
    CRCNotEqual,
    IdentityElement,
    InvalidCharacter,
    InvalidLength,
    InvalidPadding,
    NoSpaceLeft,
};

pub fn Secret(comptime Key: type) type {
    return struct {
        static: Keypair,
        remote_public: Key,
        pre_shared: Key,

        const Self = @This();
        const Keypair = key.Keypair(Key);

        const crc_len = 4;
        const bytes_len = (3 * Key.len) + crc_len;
        const base64_len = (bytes_len + 2) / 3 * 4;
        const hex_len = bytes_len * 2;

        pub fn decode(secret: []const u8) Error!Self {
            var decoded = std.mem.zeroes([bytes_len]u8);

            switch (secret.len) {
                Self.base64_len => try base64URLDecode(&decoded, secret),
                Self.hex_len => try hexDecode(&decoded, secret),
                else => return error.InvalidLength,
            }

            try verifyCRC(&decoded);

            return .{
                .static = try Keypair.init(Key.copy(decoded[0..Key.len])),
                .remote_public = Key.copy(decoded[Key.len .. 2 * Key.len]),
                .pre_shared = Key.copy(decoded[2 * Key.len .. 3 * Key.len]),
            };
        }

        fn verifyCRC(decoded: []const u8) Error!void {
            const checksum1 = std.mem.readIntSliceLittle(u32, decoded[3 * Key.len ..]);
            const checksum2 = std.hash.Crc32.hash(decoded[0 .. 3 * Key.len]);

            if (checksum1 != checksum2) {
                return error.CRCNotEqual;
            }
        }

        fn base64URLDecode(dest: []u8, source: []const u8) Error!void {
            return std.base64.Base64Decoder.decode(&std.base64.url_safe.Decoder, dest, source);
        }

        fn hexDecode(dest: []u8, source: []const u8) Error!void {
            _ = try std.fmt.hexToBytes(dest, source);
        }
    };
}
