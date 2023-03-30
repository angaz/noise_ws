# Noise KKpsk2 for the browser

## Test example:

```javascript
function humanFileSize(size) {
  var i = size == 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
  return (size / Math.pow(1024, i)).toFixed(2) * 1 + ' ' + ['B', 'kB', 'MB', 'GB', 'TB'][i];
}

function logAllocated() {
  console.log(`${bytesAllocated() / 65536} pages, ${humanFileSize(bytesAllocated())}`);
}

function test() {
  logAllocated();

  const client = new NoiseSession(true, "o9dBpAqMvvgi78SUqKX6svFOTFjZTwsCOyAjooP-Kq5YOHQWn-ITYWISQs4B27W3bOeVc4q9cK3DIgktTp2lJEgXARNRdvHZ8uLiZ5YQ3MY8vBB_VpQcHaJlDUV_0jWHb5QeAg==");
  const server = new NoiseSession(false, "7018dffcd5deb5582a0f3831cff9b6c7edd3ac56c08d3a5343d5b5e3a5a9f3150705b3268b6dcb40d7e2a22da34d708ec06f651e3b9a43d1528d6e54e2309618481701135176f1d9f2e2e2679610dcc63cbc107f56941c1da2650d457fd23587e119c2cf");
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  logAllocated();
  const start = Date.now();

  const iterations = 10;
  for (let i = 0; i < iterations; i++) {
    const e1 = client.encrypt(encoder.encode("This is my message. Keep it safe."));
    const d1 = decoder.decode(server.decrypt(e1));
    console.log(d1);
    const e2 = server.encrypt(encoder.encode("Don't worry, your message is safe."));
    const d2 = decoder.decode(client.decrypt(e2));
    console.log(d2)
  }

  client.deinit();
  server.deinit();

  const end = Date.now();
  const duration = (end - start) / 1000;

  logAllocated();
  console.log(`${(iterations/duration).toFixed(2)} messages per second`);
}

test();
```
