const std = @import("std");
const handshake = @import("./handshake.zig");
const key = @import("./key.zig");
const Allocator = std.mem.Allocator;
const HandshakeState = handshake.HandshakeState;
const Key = key.Key;
const KEY_LEN = key.KEY_LEN;

pub const NoiseSession = struct {
    secret: []const u8 = undefined,
    handshake: HandshakeState = undefined,

    const protocolName = "Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s";
    const Self = @This();

    pub fn init(allocator: Allocator, secret: []const u8) !*NoiseSession {
        const session = try allocator.create(NoiseSession);
        session.secret = try allocator.dupe(u8, secret);
        session.handshake = HandshakeState.init("asdf");

        return session;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.destroy(self);
    }

    pub fn encryptMessage(self: *Self, allocator: Allocator, message: []const u8) ![]const u8 {
        var msg = try std.mem.concat(allocator, u8, &[_][]const u8{ self.secret, message });

        for (msg, 0..) |c, i| {
            if (i % 2 == 0) {
                if (std.ascii.isLower(c)) {
                    msg[i] = std.ascii.toUpper(c);
                }
            } else {
                if (std.ascii.isUpper(c)) {
                    msg[i] = std.ascii.toLower(c);
                }
            }
        }

        return msg;
    }
};
