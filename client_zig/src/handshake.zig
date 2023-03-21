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
    pub fn initInitiator(
        protocol_name: []const u8,
        prologue: []const u8,
        static_key: Keypair,
        remote_static: Key,
        pre_shared_key: Key,
    ) Self {
        var symmetric_state = SymmetricState.init(protocol_name);
        symmetric_state.mixHash(prologue);
        symmetric_state.mixHash(&static_key.public.key);
        symmetric_state.mixHash(&remote_static.key);

        return .{
            .symmetric_state = symmetric_state,
            .static_key = static_key,
            .ephemeral_key = Keypair.empty(),
            .remote_static = remote_static,
            .remote_ephemeral = Key.empty(),
            .pre_shared_key = pre_shared_key,
        };
    }
};
