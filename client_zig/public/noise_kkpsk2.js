let noiseWASM;

WebAssembly
  .instantiateStreaming(fetch("wasm/noise_kkpsk2.wasm"), {})
  .then(result => {
    noiseWASM = result.instance;
    console.log(noiseWASM.exports);
  });
