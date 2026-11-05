const worker = new Worker(new URL("./worker.js", import.meta.url), {
  type: "module",
});

const fileInput = document.querySelector("#capture");
const decodePanel = document.querySelector("#decode-panel");
const dropZone = document.querySelector("#drop-zone");
const decoding = document.querySelector("#decoding");
const decodeAnotherButton = document.querySelector("#decode-another-button");
const downloadButton = document.querySelector("#download-button");
const downloadAchievementsButton = document.querySelector(
  "#download-achievements-button",
);
const status = document.querySelector("#status");
const result = document.querySelector("#result");
const stats = document.querySelector("#stats");
const extractList = document.querySelector("#extract-list");
const warnings = document.querySelector("#warnings");
const warningList = document.querySelector("#warning-list");
const output = document.querySelector("#output");
const achievementsOutput = document.querySelector("#achievements-output");
const previewNote = document.querySelector("#preview-note");

const PREVIEW_LIMIT = 200_000;

let selectedFile = null;
let report = null;

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0] ?? null;
  if (file) startDecode(file);
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
  if (file) startDecode(file);
});

decodeAnotherButton.addEventListener("click", resetView);

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

downloadAchievementsButton.addEventListener("click", () => {
  if (!report?.achievements) return;

  const json = JSON.stringify(report.achievements, null, 2);
  const blob = new Blob([json, "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${selectedFile.name.replace(/\.(pcapng|pcap)$/i, "")}.achievements.json`;
  link.click();
  URL.revokeObjectURL(url);
});

worker.addEventListener("message", (event) => {
  const message = event.data;
  if (!message.ok) {
    finishDecoding(false);
    status.textContent = `Decode failed: ${message.error}`;
    status.classList.add("error");
    return;
  }

  report = JSON.parse(message.result);
  finishDecoding(true);
  decodePanel.hidden = true;
  render(report);
});

worker.addEventListener("error", (event) => {
  finishDecoding(false);
  status.textContent = `Worker error: ${event.message}`;
  status.classList.add("error");
});

function startDecode(file) {
  selectedFile = file;
  report = null;
  result.hidden = true;
  decodePanel.hidden = false;
  dropZone.hidden = true;
  decoding.hidden = false;
  downloadButton.disabled = true;
  downloadAchievementsButton.disabled = true;
  output.textContent = "";
  achievementsOutput.textContent = "";
  status.classList.remove("error");
  status.textContent = "";
  fileInput.disabled = true;

  worker.postMessage({
    file,
    options: {
      fakeInitialize4thLine: false,
    },
  });
}

function finishDecoding(success) {
  decoding.hidden = true;
  fileInput.disabled = false;

  if (!success) {
    dropZone.hidden = false;
    decodePanel.hidden = false;
  }
}

function resetView() {
  selectedFile = null;
  report = null;
  fileInput.value = "";
  fileInput.disabled = false;
  decodePanel.hidden = false;
  dropZone.hidden = false;
  decoding.hidden = true;
  result.hidden = true;
  downloadButton.disabled = true;
  downloadAchievementsButton.disabled = true;
  status.textContent = "";
  status.classList.remove("error");
  output.textContent = "";
  achievementsOutput.textContent = "";
  previewNote.hidden = true;
}

function render(data) {
  const counts = [
    ["Packets read", data.capture.packets],
    ["Game packets", data.capture.gamePackets],
    ["Commands decoded", data.decode.commands],
    ["Handshakes", data.decode.handshakes],
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

  renderExtracted(data);

  const achievements = data.achievements?.gi_achievements?.length ?? 0;
  downloadAchievementsButton.disabled = achievements === 0;
  downloadButton.disabled = !hasGoodData(data.good);
  achievementsOutput.textContent = JSON.stringify(
    data.achievements ?? { gi_achievements: [] },
    null,
    2,
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
}

function hasGoodData(good) {
  const materials = good.materials ?? {};
  return (
    good.characters.length > 0 ||
    good.artifacts.length > 0 ||
    good.weapons.length > 0 ||
    Object.keys(materials).length > 0
  );
}

function renderExtracted(data) {
  const materials = data.good.materials ?? {};
  const itemNames = Object.keys(materials).filter((name) => name !== "Mora");
  const mora = Number(materials.Mora ?? 0);

  const entries = [
    { label: "Characters", count: data.good.characters.length },
    { label: "Artifacts", count: data.good.artifacts.length },
    { label: "Weapons", count: data.good.weapons.length },
    { label: "Items", count: itemNames.length, unit: "type" },
    { label: "Mora", count: mora, format: "number" },
    {
      label: "Achievements",
      count: data.achievements?.gi_achievements?.length ?? 0,
    },
  ];

  extractList.replaceChildren(
    ...entries.map(({ label, count, unit, format }) => {
      const found = count > 0;
      const item = document.createElement("li");
      item.className = `extract-item ${found ? "found" : "missing"}`;

      const mark = document.createElement("span");
      mark.className = "extract-mark";
      mark.setAttribute("aria-hidden", "true");
      mark.textContent = found ? "✓" : "✕";

      const name = document.createElement("span");
      name.className = "extract-label";
      name.textContent = label;

      const value = document.createElement("span");
      value.className = "extract-value";
      if (!found) {
        value.textContent = "none";
      } else if (format === "number") {
        value.textContent = count.toLocaleString();
      } else if (unit) {
        value.textContent = `${count} ${unit}${count === 1 ? "" : "s"}`;
      } else {
        value.textContent = String(count);
      }

      const status = document.createElement("span");
      status.className = "visually-hidden";
      status.textContent = found ? "extracted" : "not extracted";

      item.append(mark, name, value, status);
      return item;
    }),
  );
}
