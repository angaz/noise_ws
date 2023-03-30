// We have no random numbers in WASM, so we have to import the function.
extern fn getRandomValues(ptr: usize, len: usize) void;

pub fn fillRandom(slice: []u8) void {
    getRandomValues(@ptrToInt(&slice), slice.len);
}
