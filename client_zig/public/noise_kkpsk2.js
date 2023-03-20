let wasmInstance;
let wasmExports;
let wasmMemory;
let ready = false;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

WebAssembly
  .instantiateStreaming(fetch("wasm/noise_kkpsk2.wasm"), {})
  .then(result => {
    wasmInstance = result.instance;
    wasmExports = wasmInstance.exports;
    wasmMemory = wasmExports.memory;
    console.log(wasmExports);

    ready = true;
  });

function alloc(size) {
  const ptr = wasmExports.alloc(size);
  if (ptr === 0) {
    throw new Error("WASM alloc failed");
  }

  return ptr
}

function free(ptr, size) {
  if (size == 0) {
    throw new Error("Cannot free 0 size array");
  }

  wasmExports.free(ptr, size);
}

function allocInputArray(bytes) {
  const size = bytes.length;
  const ptr = alloc(size);

  const arr = new Uint8Array(wasmMemory.buffer, ptr, size);
  arr.set(bytes);

  return [ptr, size];
}

function allocInputString(str) {
  const bytes = encoder.encode(str);
  return allocInputArray(bytes);
}

function freeOutputArray(ptr) {
  const [arrPtr, arrLen] = new Uint32Array(wasmMemory.buffer, ptr, 2);
  console.log(ptr);
  free(arrPtr, arrLen);
  free(ptr, 8);
}

export function readOutputArray(ptr) {
  const [arrPtr, arrLen] = new Uint32Array(wasmMemory.buffer, ptr, 2);
  const arr = new Uint8Array(wasmMemory.buffer, arrPtr, arrLen);
  return arr.slice();
}

export function readOutputString(ptr) {
  const arr = readOutputArray(ptr);
  return decoder.decode(arr);
}

export class NoiseSession {
  constructor(secret) {
    if (ready === false) {
      throw new Error("Webassembly not ready");
    }

    const [secretPtr, secretLen] = allocInputString(secret);
    this.ptr = wasmExports.sessionInit(secretPtr, secretLen);
    free(secretPtr);
  }

  deinit() {
    wasmExports.sessionDeinit(this.ptr);
  }

  encryptMessage(message) {
    const [messagePtr, messageLen] = allocInputArray(message);
    const encryptedPtr = wasmExports.encryptMessage(this.ptr, messagePtr, messageLen);
    free(messagePtr, messageLen);

    const outArray = readOutputArray(encryptedPtr);
    freeOutputArray(encryptedPtr);

    return outArray;
  }
}

export function bytesAllocated() {
  return wasmMemory.buffer.byteLength;
}
