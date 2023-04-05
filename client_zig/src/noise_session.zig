const std = @import("std");
const HandshakeState = @import("handshake.zig").HandshakeState;
const Hash = @import("hash.zig").Hash;
const CipherState = @import("cipher_state.zig").CipherState;
const Ciphertext = @import("ciphertext.zig").Ciphertext;
const message = @import("message.zig");
const key = @import("key.zig");
const Allocator = std.mem.Allocator;
const Key = key.Key;
const Keypair = key.Keypair;
const secret = @import("secret.zig");

pub const InitError = error{
    CRCNotEqual,
    IdentityElement,
    InvalidCharacter,
    InvalidLength,
    InvalidPadding,
    NoSpaceLeft,
    OutOfMemory,
};

pub const DecryptMessageAError = error{
    TooOld,
};

pub const DecryptMessageBError = error{
    NotZero,
};

const Secret = secret.Secret(key.Key32);

pub const NoiseSession = struct {
    secret: Secret,
    handshake: HandshakeState,
    initiator: bool,
    handshake_hash: Hash,
    cipher_state_local: CipherState,
    cipher_state_remote: CipherState,
    message_count: u128,

    const protocol_name = "Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s";
    const Self = @This();

    pub fn init(
        allocator: Allocator,
        initiator: bool,
        secret_str: []const u8,
        prologue: []const u8,
    ) InitError!*NoiseSession {
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
        session.handshake_hash = Hash.empty();
        session.cipher_state_local = CipherState.empty();
        session.cipher_state_remote = CipherState.empty();

        return session;
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        allocator.destroy(self);
    }

    pub fn encryptAndEncodeMessageA(self: *Self, allocator: Allocator) ![]const u8 {
        const timestamp = std.time.milliTimestamp();
        var plaintext = try allocator.alloc(u8, @sizeOf(@TypeOf(timestamp)));
        defer allocator.free(plaintext);
        std.mem.writeIntSliceLittle(i64, plaintext, timestamp);

        const ciphertext = try self.handshake.encryptMessageA(allocator, plaintext);
        defer ciphertext.deinit(allocator);

        const msg = message.MessageHandshake{
            .message_type = message.MessageType.handshake_initiation,
            .ephemeral = self.handshake.ephemeral_key.public,
            .ciphertext = ciphertext,
        };
        return try msg.encode(allocator);
    }

    pub fn encryptAndEncodeMessageB(self: *Self, allocator: Allocator) ![]const u8 {
        const plaintext = std.mem.zeroes([16]u8);
        const ciphertext = try self.handshake.encryptMessageB(
            allocator,
            plaintext,
            &self.cipher_state_local,
            &self.cipher_state_remote,
        );
        defer ciphertext.deinit(allocator);

        const msg = message.MessageHandshake{
            .message_type = message.MessageType.handshake_response,
            .ephemeral = self.handshake.ephemeral_key.public,
            .ciphertext = ciphertext,
        };
        return try msg.encode(allocator);
    }

    pub fn encryptAndEncode(self: *Self, allocator: Allocator, plaintext: []const u8) ![]const u8 {
        const ciphertext = if (self.initiator)
            try self.cipher_state_local.encryptWithAd(allocator, "", plaintext)
        else
            try self.cipher_state_remote.encryptWithAd(allocator, "", plaintext);
        defer ciphertext.deinit(allocator);

        const msg = message.MessageData{
            .message_type = message.MessageType.data,
            .ciphertext = ciphertext,
        };
        return try msg.encode(allocator);
    }

    pub fn decodeAndDecryptMessageA(self: *Self, allocator: Allocator, ciphertext: []const u8) !void {
        const timestamp = std.time.milliTimestamp();

        const msg = message.MessageHandshake.readFrom(ciphertext);
        const plaintext = try self.handshake.decryptMessageA(allocator, msg);
        defer allocator.free(plaintext);

        const msg_timestamp = std.mem.readIntSliceLittle(i64, plaintext);

        if (std.math.absInt(msg_timestamp - timestamp) > 2000) {
            return error.TooOld;
        }
    }

    pub fn decodeAndDecryptMessageB(self: *Self, allocator: Allocator, ciphertext: []const u8) !void {
        const msg = message.MessageHandshake.readFrom(ciphertext);
        const plaintext = try self.handshake.decryptMessageB(
            allocator,
            msg,
            &self.cipher_state_local,
            &self.cipher_state_remote,
        );
        defer allocator.free(plaintext);

        // TODO: Yeah it's not really constant time, but I tried.
        var a: u8 = 0;
        for (plaintext) |c| {
            a |= c;
        }
        if (a != 0) {
            return error.NotZero;
        }
    }

    pub fn decodeAndDecrypt(self: *Self, allocator: Allocator, plaintext: []const u8) ![]const u8 {
        const msg = message.MessageData.readFrom(plaintext);

        if (self.initiator) {
            return try self.cipher_state_remote.decryptWithAd(allocator, "", msg.ciphertext);
        } else {
            return try self.cipher_state_local.decryptWithAd(allocator, "", msg.ciphertext);
        }
    }
};
