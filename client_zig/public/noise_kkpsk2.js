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

function free(ptr) {
  wasmExports.free(ptr);
}

function allocArray(bytes) {
  const ptr = alloc(bytes.length);
  const arr = new Uint8Array(wasmMemory.buffer, ptr, bytes.length);

  for (let i = 0; i < bytes.length; i++) {
    arr[i] = bytes[i];
  }

  return [ptr, bytes.length];
}

function allocString(str) {
  const bytes = encoder.encode(str);
  return allocArray(bytes);
}

export function readArray(ptr) {
  const [arrPtr, arrLen] = new Uint32Array(wasmMemory.buffer, ptr, 2);
  const arr = new Uint8Array(wasmMemory.buffer, arrPtr, arrLen);

  const outArr = new Uint8Array(arrLen);
  for (let i = 0; i < arrLen; i++) {
    outArr[i] = arr[i];
  }

  // free(arrPtr);

  return outArr;
}

export function readString(ptr) {
  const arr = readArray(ptr);
  return decoder.decode(arr);
}

export class NoiseSession {
  constructor(secret) {
    if (ready === false) {
      throw new Error("Webassembly not ready");
    }

    const [secretPtr, secretLen] = allocString(secret);
    this.ptr = wasmExports.sessionInit(secretPtr, secretLen);
    free(secretPtr);
  }

  encryptMessage(message) {
    const [messagePtr, messageLen] = allocArray(message);
    const encryptedPtr = wasmExports.encryptMessage(this.ptr, messagePtr, messageLen);
    // free(messagePtr);

    const outArr = readArray(encryptedPtr);
    // free(encryptedPtr);

    return outArr;
  }
}
