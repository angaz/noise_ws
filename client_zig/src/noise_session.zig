const std = @import("std");
const HandshakeState = @import("./handshake.zig").HandshakeState;
const Hash = @import("./hash.zig").Hash;
const CipherState = @import("./cipher_state.zig").CipherState;
const Message = @import("message.zig").Message;
const key = @import("./key.zig");
const Allocator = std.mem.Allocator;
const Key = key.Key;
const Keypair = key.Keypair;

const CRCError = error{
    NotEqual,
};

const Secret = struct {
    static: Keypair,
    remote_public: Key,
    pre_shared: Key,

    const Self = @This();

    const crc_len = 4;
    const bytes_len = (3 * Key.len) + crc_len;
    const base64_len = (bytes_len + 2) / 3 * 4;
    const hex_len = bytes_len * 2;

    pub fn decode(secret: []const u8) !Self {
        var decoded = std.mem.zeroes([Self.bytes_len]u8);

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

    fn verifyCRC(decoded: []const u8) CRCError!void {
        const checksum1 = std.mem.readIntSliceLittle(u32, decoded[3 * Key.len ..]);
        const checksum2 = std.hash.Crc32.hash(decoded[0 .. 3 * Key.len]);

        if (checksum1 != checksum2) {
            return CRCError.NotEqual;
        }
    }

    fn base64URLDecode(dest: []u8, source: []const u8) std.base64.Error!void {
        return std.base64.Base64Decoder.decode(&std.base64.url_safe.Decoder, dest, source);
    }

    fn hexDecode(dest: []u8, source: []const u8) !void {
        _ = try std.fmt.hexToBytes(dest, source);
    }
};

pub const NoiseSession = struct {
    secret: Secret,
    handshake: HandshakeState,
    initiator: bool,
    handshake_hash: Hash = Hash.empty(),
    cipher_state_local: CipherState = CipherState.empty(),
    cipher_state_remote: CipherState = CipherState.empty(),
    message_count: u128 = 0,
    transport: bool = false,

    const protocol_name = "Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s";
    const Self = @This();

    pub fn init(
        allocator: Allocator,
        initiator: bool,
        secret_str: []const u8,
        prologue: []const u8,
    ) !*NoiseSession {
        const session = try allocator.create(NoiseSession);
        session.secret = try Secret.decode(secret_str);
        session.handshake = HandshakeState.init(
            initiator,
            protocol_name,
            prologue,
            session.secret.static,
            session.secret.remote_public,
            session.secret.pre_shared,
        );
        session.initiator = initiator;

        return session;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.destroy(self);
    }

    pub fn encrypt(self: *Self, allocator: Allocator, plaintext: []const u8) !Message {
        defer self.message_count += 1;

        if (self.message_count == 0) {
            return try self.handshake.encryptMessageA(allocator, plaintext);
        }
        if (self.message_count == 1) {
            return try self.handshake.encryptMessageB(
                allocator,
                plaintext,
                &self.cipher_state_local,
                &self.cipher_state_remote,
            );
        }

        if (self.initiator) {
            return try self.cipher_state_local.encryptWithAd(allocator, "", plaintext);
        } else {
            return try self.cipher_state_remote.encryptWithAd(allocator, "", plaintext);
        }
    }

    pub fn encryptAndEncode(self: *Self, allocator: Allocator, plaintext: []const u8) ![]const u8 {
        const message = try self.encrypt(allocator, plaintext);
        const encoded = message.encode(allocator);
        allocator.free(message.ciphertext);
        return encoded;
    }

    pub fn decrypt(self: *Self, allocator: Allocator, message: Message) ![]const u8 {
        defer self.message_count += 1;

        if (self.message_count == 0) {
            return try self.handshake.decryptMessageA(allocator, message);
        }
        if (self.message_count == 1) {
            return try self.handshake.decryptMessageB(
                allocator,
                message,
                &self.cipher_state_local,
                &self.cipher_state_remote,
            );
        }

        if (self.initiator) {
            return try self.cipher_state_remote.decryptWithAd(allocator, "", message);
        } else {
            return try self.cipher_state_local.decryptWithAd(allocator, "", message);
        }
    }

    pub fn decodeAndDecrypt(self: *Self, allocator: Allocator, message: []const u8) ![]const u8 {
        const decoded = try Message.decode(message);
        return try self.decrypt(allocator, decoded);
    }
};
