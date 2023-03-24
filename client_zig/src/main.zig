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
    var prologue = std.mem.zeroes([8]u8);
    std.mem.writeIntLittle(i64, &prologue, 42);

    var noise = NoiseSession.init(wasmAllocator, true, secret[0..secretSize], prologue[0..]) catch |err| {
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

fn exportArray(arr: []const u8) usize {
    var mem = wasmAllocator.alloc(usize, 2) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    mem[0] = @ptrToInt(arr.ptr);
    mem[1] = arr.len;
    return @ptrToInt(mem.ptr);
}

export fn encrypt(session: *NoiseSession, plaintext: [*]const u8, plaintextLen: usize) usize {
    const out = session.encryptAndEncode(wasmAllocator, plaintext[0..plaintextLen]) catch |err| {
        switch (err) {
            else => {
                return 0;
            },
        }
    };

    return exportArray(out);
}
