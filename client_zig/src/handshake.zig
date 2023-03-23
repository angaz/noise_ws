const std = @import("std");
const SymmetricState = @import("./symmetric_state.zig").SymmetricState;
const key = @import("./key.zig");
const Allocator = std.mem.Allocator;
const Key = key.Key;
const Keypair = key.Keypair;

fn initSymmetricState(
    initiator: bool,
    protocol_name: []const u8,
    prologue: []const u8,
    static_key: Keypair,
    remote_static: Key,
) SymmetricState {
    var symmetric_state = SymmetricState.init(protocol_name);
    symmetric_state.mixHash(prologue);
    if (initiator) {
        symmetric_state.mixHash(&static_key.public.key);
        symmetric_state.mixHash(&remote_static.key);
    } else {
        symmetric_state.mixHash(&remote_static.key);
        symmetric_state.mixHash(&static_key.public.key);
    }

    return symmetric_state;
}

pub const HandshakeState = struct {
    symmetric_state: SymmetricState,
    static_key: Keypair,
    ephemeral_key: Keypair,
    remote_static: Key,
    remote_ephemeral: Key,
    pre_shared_key: Key,

    const Self = @This();

    pub fn init(
        initiator: bool,
        protocol_name: []const u8,
        prologue: []const u8,
        static_key: Keypair,
        remote_static: Key,
        pre_shared_key: Key,
    ) Self {
        return .{
            .symmetric_state = initSymmetricState(
                initiator,
                protocol_name,
                prologue,
                static_key,
                remote_static,
            ),
            .static_key = static_key,
            .ephemeral_key = Keypair.empty(),
            .remote_static = remote_static,
            .remote_ephemeral = Key.empty(),
            .pre_shared_key = pre_shared_key,
        };
    }

    pub fn encryptMessageA(self: *Self, allocator: Allocator, payload: []const u8) ![]const u8 {
        self.ephemeral_key = Keypair.genKeypair();
        self.symmetric_state.mixHash(self.ephemeral_key.public);
        self.symmetric_state.mixKey(self.ephemeral_key.public);
        self.symmetric_state.mixKey(try self.ephemeral_key.dh(self.remote_static));
        self.symmetric_state.mixKey(try self.static_key.dh(self.remote_static));

        return try self.symmetric_state.encryptAndHash(allocator, payload);
    }

    pub fn encryptMessageB(self: *Self, allocator: Allocator, payload: []const u8) ![]const u8 {
        _ = payload;
        _ = allocator;
        self.ephemeral_key = Keypair.genKeypair();
        self.symmetric_state.mixHash(self.ephemeral_key.public);
        self.symmetric_state.mixKey(self.ephemeral_key.public);
        self.symmetric_state.mixKey(try self.ephemeral_key.dh(self.remote_ephemeral));
        self.symmetric_state.mixKey(try self.static_key.dh(self.remote_static));
    }
};
