const std = @import("std");
const Allocator = std.mem.Allocator;
const wasmAllocator = std.heap.wasm_allocator;
const noise_session = @import("./noise_session.zig");
const NoiseSession = noise_session.NoiseSession;

export fn alloc(size: usize) usize {
    var mem = wasmAllocator.alloc(u8, size) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    return @ptrToInt(mem.ptr);
}

export fn realloc(ptr: [*]u8, originalSize: usize, size: usize) usize {
    var mem = wasmAllocator.realloc(ptr[0..originalSize], size) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    return @ptrToInt(mem.ptr);
}

export fn free(ptr: [*]u8, size: usize) void {
    wasmAllocator.free(ptr[0..size]);
}

export fn sessionInit(secret: [*]const u8, secretSize: usize) usize {
    var noise = NoiseSession.init(wasmAllocator, secret[0..secretSize]) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };
    return @ptrToInt(noise);
}

export fn sessionDeinit(session: *NoiseSession) void {
    session.deinit(wasmAllocator);
}

fn exportArray(str: []const u8) usize {
    var mem = wasmAllocator.alloc(usize, 2) catch |err| {
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
    const out = session.encryptMessage(wasmAllocator, message[0..messageSize]) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };
    return exportArray(out);
}
