const SymmetricState = @import("./symmetric_state.zig").SymmetricState;
const key = @import("./key.zig");
const Key = key.Key;
const Keypair = key.Keypair;

pub const HandshakeState = struct {
    symmetric_state: SymmetricState,
    static_key: Keypair,
    ephemeral_key: Keypair,
    remote_static: Key,
    remote_ephemeral: Key,
    pre_shared_key: Key,

    const Self = @This();

    /// The prologue is a bit of data transferred before the session starts.
    /// It forms part of the state to make sure it was not modified in transit.
    pub fn init(
        protocolName: []const u8,
        prologue: []const u8,
        static: Keypair,
        remote_static: Keypair,
        pre_shared_key: Key,
    ) Self {
        _ = pre_shared_key;
        _ = remote_static;
        _ = static;
        _ = prologue;
        _ = protocolName;
        return .{};
    }
};
