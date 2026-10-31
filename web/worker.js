import init, { decode } from "./pkg/post_irminsul.js";

let initialised = null;

self.addEventListener("message", async (event) => {
  const { file, options } = event.data;

  try {
    initialised ??= init();
    await initialised;

    const bytes = new Uint8Array(await file.arrayBuffer());
    const result = decode(bytes, JSON.stringify(options));
    self.postMessage({ ok: true, result });
  } catch (error) {
    const message = error?.message ?? String(error);
    self.postMessage({ ok: false, error: message });
  }
});
