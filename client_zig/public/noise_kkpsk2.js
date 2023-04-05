let wasmInstance;
let wasmExports;
let wasmMemory;
let ready = false;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

WebAssembly
  .instantiateStreaming(fetch("wasm/noise_kkpsk2.wasm"), {
    env: {
      getRandomValues: (ptr, size) => {
        const arr = new Uint8Array(wasmMemory.buffer, ptr, size);
        crypto.getRandomValues(arr);
      },
      throw: (ptr, size) => {
        throw new Error(decoder.decode(new Uint8Array(wasmMemory.buffer, ptr, size)));
      },
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
  const [arrPtr, arrLen] = extractArrayPointerLength(ptr);
  if (arrPtr === 0) {
    throw new Error("Pointer is 0");
  }

  free(arrPtr, arrLen);
  free(ptr, 8);
}

function extractArrayPointerLength(ptr) {
  if (ptr === 0) {
    throw new Error("Pointer is 0");
  }

  return new Uint32Array(wasmMemory.buffer, ptr, 2);
}

export function readOutputArray(ptr) {
  const [arrPtr, arrLen] = extractArrayPointerLength(ptr);
  if (arrPtr === 0) {
    throw new Error("Pointer is 0");
  }

  const arr = new Uint8Array(wasmMemory.buffer, arrPtr, arrLen);
  return arr.slice();
}

export function readOutputString(ptr) {
  const arr = readOutputArray(ptr);
  return decoder.decode(arr);
}

export class NoiseSession {
  constructor(initiator, secret, onMessageCB) {
    if (ready === false) {
      throw new Error("Webassembly not ready");
    }

    this.onMessageCB = onMessageCB;

    const [secretPtr, secretLen] = allocInputString(secret);
    this.ptr = wasmExports.sessionInit(initiator, secretPtr, secretLen);
    free(secretPtr);

    this.ready = false;
  }

  onMessage(event) {
    const { data } = event;

    // Data message
    if (data[0] == 3) {
      const plaintext = this.decrypt(data);
      this.onMessageCB(plaintext);
      return;
    }

    // Handshake response message
    if (data[0] == 2) {
      this.decryptB(data);
      return;
    }
  }

  connect(hostname) {
    this.websocket = new Websocket(hostname);
    this.websocket.send(this.encryptA());
    this.websocket.addEventListener("message", this.onMessage);
  }

  deinit() {
    wasmExports.sessionDeinit(this.ptr);
  }

  encryptA() {
    const ciphertextPtr = wasmExports.encryptA(this.ptr);
    const ciphertext = readOutputArray(ciphertextPtr);
    freeOutputArray(ciphertextPtr);
    return ciphertext;
  }

  encryptB() {
    const ciphertextPtr = wasmExports.encryptB(this.ptr);
    const ciphertext = readOutputArray(ciphertextPtr);
    freeOutputArray(ciphertextPtr);
    return ciphertext;
  }

  encrypt(plaintext) {
    const [plaintextPtr, plaintextLen] = allocInputArray(plaintext);
    const ciphertextPtr = wasmExports.encrypt(this.ptr, plaintextPtr, plaintextLen);
    free(plaintextPtr, plaintextLen);

    const ciphertext = readOutputArray(ciphertextPtr);
    freeOutputArray(ciphertextPtr);

    return ciphertext;
  }

  decryptA(ciphertext) {
    const [ciphertextPtr, ciphertextLen] = allocInputArray(ciphertext);
    wasmExports.decryptA(this.ptr, ciphertextPtr, ciphertextLen);
    free(ciphertextPtr, ciphertextLen);
  }

  decryptB(ciphertext) {
    const [ciphertextPtr, ciphertextLen] = allocInputArray(ciphertext);
    wasmExports.decryptB(this.ptr, ciphertextPtr, ciphertextLen);
    free(ciphertextPtr, ciphertextLen);
  }

  decrypt(ciphertext) {
    const [ciphertextPtr, ciphertextLen] = allocInputArray(ciphertext);
    const plaintextPtr = wasmExports.decrypt(this.ptr, ciphertextPtr, ciphertextLen);
    free(ciphertextPtr, ciphertextLen);

    const plaintext = readOutputArray(plaintextPtr);
    freeOutputArray(plaintextPtr);

    return plaintext;
  }
}

export function bytesAllocated() {
  return wasmMemory.buffer.byteLength;
}
