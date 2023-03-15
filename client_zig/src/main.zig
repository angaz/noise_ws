const std = @import("std");
const defaultAllocator = std.heap.wasm_allocator;

const NOISE_SESSION_SIZE = @sizeOf(NoiseSession);

export fn alloc(size: usize) usize {
    var mem = defaultAllocator.alloc([*]u8, size) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };
    return @ptrToInt(mem.ptr);
}

export fn realloc(ptr: usize, size: usize) usize {
    var mem = defaultAllocator.realloc(@intToPtr([]u8, ptr), size) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    return @ptrToInt(mem.ptr);
}

export fn free(ptr: usize) void {
    defaultAllocator.free(@intToPtr([]u8, ptr));
}

const NoiseSession = struct {
    const Self = @This();

    pub fn create(allocator: std.mem.Allocator, secret: []const u8) !*NoiseSession {
        _ = secret;
        const session = try allocator.create(NoiseSession);
        return session;
    }

    pub fn destroy(self: *Self, allocator: *std.mem.Allocator) void {
        allocator.destroy(self);
    }

    pub fn encryptMessage(self: *Self, message: []const u8) []const u8 {
        _ = self;
        return message;
    }
};

export fn initializeSession(secret: [*]const u8, secretSize: usize) usize {
    _ = secretSize;
    _ = secret;
    var noise = NoiseSession.create(defaultAllocator, "asdf1234") catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };
    return @ptrToInt(noise);
}

fn string(str: []const u8) usize {
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
    const out = session.encryptMessage(message[0..messageSize]);
    return string(out);
}
