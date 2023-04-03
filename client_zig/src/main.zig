const std = @import("std");
const Allocator = std.mem.Allocator;
const wasmAllocator = std.heap.wasm_allocator;
const noise_session = @import("./noise_session.zig");
const NoiseSession = noise_session.NoiseSession;

extern fn throw(ptr: usize, size: usize) void;

fn throwError(err: []const u8) void {
    throw(@ptrToInt(err), err.len);
}

export fn alloc(size: usize) usize {
    var mem = wasmAllocator.alloc(u8, size) catch |err| {
        switch (err) {
            else => {
                throwError("alloc failed");
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
                throwError("realloc failed");
                return 0;
            },
        }
    };

    return @ptrToInt(mem.ptr);
}

export fn free(ptr: [*]u8, size: usize) void {
    wasmAllocator.free(ptr[0..size]);
}

export fn sessionInit(initiator: bool, secret: [*]const u8, secretSize: usize) usize {
    var prologue = std.mem.zeroes([8]u8);
    std.mem.writeIntLittle(i64, &prologue, 42);

    var noise = NoiseSession.init(
        wasmAllocator,
        initiator,
        secret[0..secretSize],
        prologue[0..],
    ) catch |err| {
        switch (err) {
            else => {
                throwError("noise session init failed");
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
                throwError("export array alloc failed");
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
                throwError("encrypt failed");
                return 0;
            },
        }
    };

    return exportArray(out);
}

export fn decrypt(session: *NoiseSession, message: [*]const u8, messageLen: usize) usize {
    const out = session.decodeAndDecrypt(wasmAllocator, message[0..messageLen]) catch |err| {
        switch (err) {
            else => {
                throwError("decrypt failed");
                return 0;
            },
        }
    };

    return exportArray(out);
}
