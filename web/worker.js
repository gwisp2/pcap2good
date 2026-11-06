import init, { decode } from "./pkg/pcap2good.js";

let initialised = null;

self.addEventListener("message", async (event) => {
  const { file } = event.data;

  try {
    initialised ??= init();
    await initialised;

    const bytes = new Uint8Array(await file.arrayBuffer());
    const result = decode(bytes);
    self.postMessage({ ok: true, result });
  } catch (error) {
    const message = error?.message ?? String(error);
    self.postMessage({ ok: false, error: message });
  }
});
