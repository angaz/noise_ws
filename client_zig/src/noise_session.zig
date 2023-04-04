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

const InitError = error{
    CRCNotEqual,
    IdentityElement,
    InvalidCharacter,
    InvalidLength,
    InvalidPadding,
    NoSpaceLeft,
    OutOfMemory,
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
        std.mem.writeIntSliceLittle(u8, plaintext, timestamp);

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
            return try self.cipher_state_remote.decryptWithAd(allocator, "", message.ciphertext);
        } else {
            return try self.cipher_state_local.decryptWithAd(allocator, "", message.ciphertext);
        }
    }

    pub fn decodeAndDecrypt(self: *Self, allocator: Allocator, message: []const u8) ![]const u8 {
        const decoded = try Message.decode(message);
        return try self.decrypt(allocator, decoded);
    }
};
