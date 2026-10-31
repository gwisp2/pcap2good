const worker = new Worker(new URL("./worker.js", import.meta.url), {
  type: "module",
});

const form = document.querySelector("#decode-form");
const fileInput = document.querySelector("#capture");
const dropZone = document.querySelector("#drop-zone");
const dropTitle = document.querySelector("#drop-title");
const dropSubtitle = document.querySelector("#drop-subtitle");
const fake4thLine = document.querySelector("#fake-4th-line");
const decodeButton = document.querySelector("#decode-button");
const downloadButton = document.querySelector("#download-button");
const status = document.querySelector("#status");
const result = document.querySelector("#result");
const stats = document.querySelector("#stats");
const warnings = document.querySelector("#warnings");
const warningList = document.querySelector("#warning-list");
const output = document.querySelector("#output");
const previewNote = document.querySelector("#preview-note");

const PREVIEW_LIMIT = 200_000;

let selectedFile = null;
let report = null;
let startedAt = 0;

fileInput.addEventListener("change", () => {
  selectFile(fileInput.files[0] ?? null);
});

// Allow choosing the same file again after a decode.
fileInput.addEventListener("click", () => {
  fileInput.value = "";
});

dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("dragging");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragging");
});

dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragging");
  const file = event.dataTransfer?.files?.[0] ?? null;
  if (file) selectFile(file);
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selectedFile) return;
  startDecode(selectedFile);
});

downloadButton.addEventListener("click", () => {
  if (!report) return;

  const json = JSON.stringify(report.good, null, 2);
  const blob = new Blob([json, "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${selectedFile.name.replace(/\.(pcapng|pcap)$/i, "")}.good.json`;
  link.click();
  URL.revokeObjectURL(url);
});

worker.addEventListener("message", (event) => {
  const message = event.data;
  if (!message.ok) {
    setBusy(false);
    status.textContent = `Decode failed: ${message.error}`;
    status.classList.add("error");
    return;
  }

  report = JSON.parse(message.result);
  const elapsed = ((performance.now() - startedAt) / 1000).toFixed(1);
  setBusy(false);
  status.textContent = `Decoded ${selectedFile.name} in ${elapsed}s.`;
  status.classList.remove("error");
  render(report);
});

worker.addEventListener("error", (event) => {
  setBusy(false);
  status.textContent = `Worker error: ${event.message}`;
  status.classList.add("error");
});

function selectFile(file) {
  selectedFile = file;
  decodeButton.disabled = !file;

  if (!file) {
    dropTitle.textContent = "Drop a capture here";
    dropSubtitle.textContent = "or click to choose a .pcap / .pcapng file";
    return;
  }

  dropTitle.textContent = file.name;
  dropSubtitle.textContent = formatBytes(file.size);
}

function startDecode(file) {
  report = null;
  result.hidden = true;
  downloadButton.hidden = true;
  output.textContent = "";
  status.classList.remove("error");
  status.textContent = `Decoding ${file.name} (${formatBytes(file.size)})…`;
  startedAt = performance.now();
  setBusy(true);

  worker.postMessage({
    file,
    options: {
      fakeInitialize4thLine: fake4thLine.checked,
    },
  });
}

function setBusy(busy) {
  decodeButton.disabled = busy || !selectedFile;
  fileInput.disabled = busy;
  fake4thLine.disabled = busy;
  dropZone.classList.toggle("busy", busy);
}

function render(data) {
  const counts = [
    ["Packets read", data.capture.packets],
    ["Game packets", data.capture.gamePackets],
    ["Commands decoded", data.decode.commands],
    ["Handshakes", data.decode.handshakes],
    ["Characters", data.good.characters.length],
    ["Artifacts", data.good.artifacts.length],
    ["Weapons", data.good.weapons.length],
  ];

  stats.replaceChildren(
    ...counts.map(([label, value]) => {
      const cell = document.createElement("div");
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = String(value);
      cell.append(dt, dd);
      return cell;
    }),
  );

  warningList.replaceChildren(
    ...data.warnings.map((warning) => {
      const item = document.createElement("li");
      const message = document.createElement("span");
      message.textContent = warning.message;
      item.append(message);
      if (warning.hint) {
        const hint = document.createElement("small");
        hint.textContent = warning.hint;
        item.append(hint);
      }
      return item;
    }),
  );
  warnings.hidden = data.warnings.length === 0;

  const json = JSON.stringify(data.good, null, 2);
  const truncated = json.length > PREVIEW_LIMIT;
  output.textContent = truncated
    ? `${json.slice(0, PREVIEW_LIMIT)}\n…`
    : json;

  previewNote.hidden = !truncated;
  previewNote.textContent = truncated
    ? "Preview truncated. Use “Download GOOD JSON” for the complete document."
    : "";

  result.hidden = false;
  downloadButton.hidden = false;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

/* Manual viewer */

const manualButton = document.querySelector("#manual-button");
const manualDialog = document.querySelector("#manual-dialog");
const manualClose = document.querySelector("#manual-close");
const manualViewport = document.querySelector("#manual-viewport");
const manualImage = document.querySelector("#manual-image");
const manualLoading = document.querySelector("#manual-loading");
const manualZoomLabel = document.querySelector("#manual-zoom");
const manualZoomIn = document.querySelector("#manual-zoom-in");
const manualZoomOut = document.querySelector("#manual-zoom-out");
const manualFit = document.querySelector("#manual-fit");
const manualActual = document.querySelector("#manual-actual");

const MANUAL_MIN_ZOOM = 0.05;
const MANUAL_MAX_ZOOM = 4;
const MANUAL_ZOOM_STEP = 1.25;

let manualLoaded = false;
let manualZoom = 1;
let manualNaturalWidth = 0;
let manualNaturalHeight = 0;
let manualDrag = null;

manualButton.addEventListener("click", openManual);
manualClose.addEventListener("click", closeManual);
manualDialog.addEventListener("click", (event) => {
  if (event.target === manualDialog) closeManual();
});
manualDialog.addEventListener("close", () => {
  if (!manualDialog.open) {
    document.body.classList.remove("manual-open");
  }
  manualDrag = null;
  manualViewport.classList.remove("dragging");
});
manualDialog.addEventListener("keydown", onManualKeyDown);

manualImage.addEventListener("load", () => {
  manualLoaded = true;
  manualNaturalWidth = manualImage.naturalWidth;
  manualNaturalHeight = manualImage.naturalHeight;
  manualLoading.hidden = true;
  fitManual();
});
manualImage.addEventListener("error", () => {
  manualLoading.textContent = "Could not load guide.png";
});

manualZoomIn.addEventListener("click", () => setManualZoom(manualZoom * MANUAL_ZOOM_STEP));
manualZoomOut.addEventListener("click", () => setManualZoom(manualZoom / MANUAL_ZOOM_STEP));
manualFit.addEventListener("click", fitManual);
manualActual.addEventListener("click", () => setManualZoom(1));

manualViewport.addEventListener("wheel", onManualWheel, { passive: false });
manualViewport.addEventListener("pointerdown", onManualPointerDown);
manualViewport.addEventListener("pointermove", onManualPointerMove);
manualViewport.addEventListener("pointerup", endManualDrag);
manualViewport.addEventListener("pointercancel", endManualDrag);

function openManual() {
  if (!manualImage.getAttribute("src")) {
    manualImage.src = "./guide.png";
  }

  document.body.classList.add("manual-open");
  manualDialog.showModal();

  if (manualLoaded) {
    fitManual();
  }
}

function closeManual() {
  manualDialog.close();
  document.body.classList.remove("manual-open");
  manualDrag = null;
  manualViewport.classList.remove("dragging");
}

function setManualZoom(next, anchor = null) {
  if (!manualLoaded) return;

  const clamped = Math.min(MANUAL_MAX_ZOOM, Math.max(MANUAL_MIN_ZOOM, next));
  if (Math.abs(clamped - manualZoom) < 0.0001) return;

  const viewportRect = manualViewport.getBoundingClientRect();
  const point = anchor ?? {
    x: viewportRect.left + manualViewport.clientWidth / 2,
    y: viewportRect.top + manualViewport.clientHeight / 2,
  };

  const before = manualImage.getBoundingClientRect();
  const imageX = (point.x - before.left) / manualZoom;
  const imageY = (point.y - before.top) / manualZoom;

  manualZoom = clamped;
  manualImage.style.width = `${manualNaturalWidth * manualZoom}px`;
  manualImage.style.height = `${manualNaturalHeight * manualZoom}px`;
  manualZoomLabel.textContent = `${Math.round(manualZoom * 100)}%`;

  const after = manualImage.getBoundingClientRect();
  manualViewport.scrollLeft += point.x - (after.left + imageX * manualZoom);
  manualViewport.scrollTop += point.y - (after.top + imageY * manualZoom);
}

function fitManual() {
  if (!manualLoaded) return;

  const width = manualViewport.clientWidth - 48;
  const height = manualViewport.clientHeight - 48;
  if (width <= 0 || height <= 0) return;

  const scale = Math.min(width / manualNaturalWidth, height / manualNaturalHeight);
  setManualZoom(Math.min(1, scale));
  manualViewport.scrollTo({ top: 0, left: 0 });
}

function onManualWheel(event) {
  if (!manualLoaded || (!event.ctrlKey && !event.metaKey)) return;

  event.preventDefault();
  const factor = Math.exp(-event.deltaY * 0.0015);
  setManualZoom(manualZoom * factor, { x: event.clientX, y: event.clientY });
}

function onManualKeyDown(event) {
  switch (event.key) {
    case "+":
    case "=":
      event.preventDefault();
      setManualZoom(manualZoom * MANUAL_ZOOM_STEP);
      break;
    case "-":
    case "_":
      event.preventDefault();
      setManualZoom(manualZoom / MANUAL_ZOOM_STEP);
      break;
    case "0":
      event.preventDefault();
      fitManual();
      break;
    case "1":
      event.preventDefault();
      setManualZoom(1);
      break;
  }
}

function onManualPointerDown(event) {
  if (!manualLoaded || event.pointerType !== "mouse" || event.button !== 0) return;
  if (!event.target.closest(".manual-canvas")) return;

  manualDrag = {
    pointerId: event.pointerId,
    x: event.clientX,
    y: event.clientY,
    left: manualViewport.scrollLeft,
    top: manualViewport.scrollTop,
  };

  manualViewport.setPointerCapture(event.pointerId);
  manualViewport.classList.add("dragging");
  event.preventDefault();
}

function onManualPointerMove(event) {
  if (!manualDrag || event.pointerId !== manualDrag.pointerId) return;

  manualViewport.scrollLeft = manualDrag.left - (event.clientX - manualDrag.x);
  manualViewport.scrollTop = manualDrag.top - (event.clientY - manualDrag.y);
}

function endManualDrag(event) {
  if (!manualDrag) return;
  if (event.pointerId !== undefined && event.pointerId !== manualDrag.pointerId) return;

  manualDrag = null;
  manualViewport.classList.remove("dragging");
}
