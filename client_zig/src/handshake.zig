pub const HandshakeState = struct {
    const Self = @This();

    pub fn init(prologue: []const u8) Self {
        _ = prologue;
        return .{};
    }
};
