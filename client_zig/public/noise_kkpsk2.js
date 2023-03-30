let wasmInstance;
let wasmExports;
let wasmMemory;
let ready = false;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

WebAssembly
  .instantiateStreaming(fetch("wasm/noise_kkpsk2.wasm"), {
    env: {
      getRandomValues,
    },
  }).then(result => {
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
  free(arrPtr, arrLen);
  free(ptr, 8);
}

function getRandomValues(ptr, len) {
  const arr = new Uint8Array(wasmMemory.buffer, ptr, len);
  crypto.getRandomValues(arr);
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
  constructor(initiator, secret) {
    if (ready === false) {
      throw new Error("Webassembly not ready");
    }

    const [secretPtr, secretLen] = allocInputString(secret);
    this.ptr = wasmExports.sessionInit(initiator, secretPtr, secretLen);
    free(secretPtr);

    if (this.ptr === 0) {
      throw new Error("NoiseSession init failed");
    }
  }

  deinit() {
    wasmExports.sessionDeinit(this.ptr);
  }

  encrypt(message) {
    const [messagePtr, messageLen] = allocInputArray(message);
    const encryptedPtr = wasmExports.encrypt(this.ptr, messagePtr, messageLen);
    free(messagePtr, messageLen);

    const outArray = readOutputArray(encryptedPtr);
    freeOutputArray(encryptedPtr);

    return outArray;
  }

  decrypt(payload) {
    const [payloadPtr, payloadLen] = allocInputArray(payload);
    const decryptedPtr = wasmExports.decrypt(this.ptr, payloadPtr, payloadLen);
    free(payloadPtr, payloadLen);

    const plaintext = readOutputArray(decryptedPtr);
    freeOutputArray(decryptedPtr);

    return plaintext;
  }
}

export function bytesAllocated() {
  return wasmMemory.buffer.byteLength;
}
