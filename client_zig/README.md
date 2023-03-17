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

  const session = new NoiseSession("Secret!!!1!");
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  logAllocated();
  const start = Date.now();

  const iterations = 1000000;
  for (let i = 0; i < iterations; i++) {
    decoder.decode(session.encryptMessage(encoder.encode("This is my message. Keep it safe.")));
  }

  session.deinit();

  const end = Date.now();
  const duration = (end - start) / 1000;

  logAllocated();
  console.log(`${(iterations/duration).toFixed(2)} messages per second`);
}

test();
```
