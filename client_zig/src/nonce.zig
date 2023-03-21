pub const Nonce = struct {
    nonce: u64 = 0,

    const Self = @This();

    pub fn init() Self {
        return .{ .nonce = 0 };
    }

    pub fn inc(self: *Self) void {
        self.n += 1;
    }
};
