const std = @import("std");
const defaultAllocator = std.heap.wasm_allocator;

export fn alloc(size: usize) usize {
    var mem = defaultAllocator.alloc(u8, size) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    return @ptrToInt(mem.ptr);
}

export fn realloc(ptr: [*]u8, originalSize: usize, size: usize) usize {
    var mem = defaultAllocator.realloc(ptr[0..originalSize], size) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    return @ptrToInt(mem.ptr);
}

export fn free(ptr: [*]u8, size: usize) void {
    defaultAllocator.free(ptr[0..size]);
}

const KEY_LEN = 32;

const Key = struct {
    key: [KEY_LEN]u8 = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, key: [KEY_LEN]u8) !Self {
        return .{
            .key = try allocator.dupe(u8, key),
        };
    }

    pub fn deinit(self: *Self, allocator: self.mem.Allocator) void {
        allocator.free(self.key);
    }
};

const Keypair = struct {
    private: Key = undefined,
    public: Key = undefined,

    const Self = @This();

    pub fn init(private: Key, public: Key) Self {
        return .{
            .private = private,
            .public = public,
        };
    }
};

const HandshakeState = struct {
    const Self = @This();

    pub fn init(prologue: []const u8) Self {
        _ = prologue;
        return .{};
    }
};
const NoiseSession = struct {
    secret: []const u8,
    handshake: HandshakeState = undefined,

    const protocolName = "Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s";
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, secret: []const u8) !*NoiseSession {
        const session = try allocator.create(NoiseSession);
        session.secret = try allocator.dupe(u8, secret);
        session.handshake = HandshakeState.init("asdf");

        return session;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }

    pub fn encryptMessage(self: *Self, allocator: std.mem.Allocator, message: []const u8) ![]const u8 {
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

export fn sessionInit(secret: [*]const u8, secretSize: usize) usize {
    var noise = NoiseSession.init(defaultAllocator, secret[0..secretSize]) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };
    return @ptrToInt(noise);
}

export fn sessionDeinit(session: *NoiseSession) void {
    session.deinit(defaultAllocator);
}

fn exportArray(str: []const u8) usize {
    var mem = defaultAllocator.alloc(usize, 2) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    mem[0] = @ptrToInt(str.ptr);
    mem[1] = str.len;
    return @ptrToInt(mem.ptr);
}

export fn encryptMessage(session: *NoiseSession, message: [*]const u8, messageSize: usize) usize {
    const out = session.encryptMessage(defaultAllocator, message[0..messageSize]) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };
    return exportArray(out);
}
