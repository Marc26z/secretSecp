import { encryptNsec, npubFromInput } from "./nip49.js";

const $ = (id) => document.getElementById(id);

const signin = $("signin");
const signedin = $("signedin");
const form = $("form");
const result = $("result");
const keyCard = $("keyCard");
const nsecInput = $("nsec");
const passInput = $("pass");
const pass2Input = $("pass2");
const lognInput = $("logn");
const workLabel = $("workLabel");
const ksbText = $("ksbText");
const encryptButton = $("encrypt");
const keyError = $("keyError");
const passError = $("passError");
const encryptError = $("encryptError");

let nsecValue = "";
let npub = "";
let ksb = 0;
let busy = false;

const ksbMessages = [
  "This key was pasted or stored unencrypted, so it has been handled insecurely.",
  "You have always kept this key encrypted.",
  "The client does not track how this key was handled.",
];

function setError(node, message) {
  node.textContent = message || "";
}

function updateWorkLabel() {
  const logn = Number(lognInput.value);
  workLabel.textContent = `2^${logn} · ${Math.round(2 ** logn / 1024)} MiB`;
}

function showSignin() {
  signin.hidden = false;
  signedin.hidden = true;
  form.hidden = true;
  result.hidden = true;
  keyCard.hidden = false;
  nsecInput.value = "";
  nsecInput.focus();
}

function clearResult() {
  result.hidden = true;
  $("resultNpub").textContent = "";
  $("resultNcrypt").textContent = "";
}

function resetAll() {
  nsecValue = "";
  npub = "";
  ksb = 0;
  busy = false;
  passInput.value = "";
  pass2Input.value = "";
  setError(keyError, "");
  setError(passError, "");
  setError(encryptError, "");
  encryptButton.disabled = false;
  encryptButton.textContent = "encrypt nsec";
  lognInput.value = "16";
  updateWorkLabel();
  document.querySelectorAll(".chip").forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.ksb === "0");
  });
  ksbText.textContent = ksbMessages[0];
  clearResult();
  showSignin();
}

async function useKey() {
  setError(keyError, "");
  const raw = nsecInput.value.trim();
  if (raw === "") {
    setError(keyError, "paste your nsec first");
    return;
  }
  if (raw.toLowerCase().startsWith("ncryptsec1")) {
    setError(keyError, "that is an ncryptsec, not an nsec");
    return;
  }
  try {
    npub = npubFromInput(raw);
  } catch (error) {
    setError(keyError, error && error.message ? error.message : "couldn't read that key");
    return;
  }
  nsecValue = raw;
  nsecInput.value = "";
  $("npub").textContent = npub;
  signin.hidden = true;
  signedin.hidden = false;
  result.hidden = true;
  keyCard.hidden = false;
  form.hidden = false;
  clearResult();
  passInput.focus();
}

function changeKey() {
  nsecValue = "";
  npub = "";
  passInput.value = "";
  pass2Input.value = "";
  setError(passError, "");
  setError(encryptError, "");
  clearResult();
  showSignin();
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {}
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {}
  document.body.removeChild(area);
  return ok;
}

async function encrypt() {
  if (busy) return;
  setError(passError, "");
  setError(encryptError, "");

  if (nsecValue.trim() === "") {
    setError(encryptError, "paste your nsec again");
    return;
  }
  if (passInput.value === "") {
    setError(encryptError, "choose a passphrase");
    return;
  }
  if (passInput.value !== pass2Input.value) {
    setError(passError, "the passphrases do not match");
    return;
  }

  busy = true;
  encryptButton.disabled = true;
  encryptButton.textContent = "encrypting… 0%";
  try {
    const output = await encryptNsec(
      { nsec: nsecValue, pass: passInput.value, logn: Number(lognInput.value), ksb },
      (progress) => {
        encryptButton.textContent = `encrypting… ${Math.round(progress * 100)}%`;
      },
    );
    nsecValue = "";
    nsecInput.value = "";
    passInput.value = "";
    pass2Input.value = "";
    npub = output.npub;
    $("resultNpub").textContent = output.npub;
    $("resultNcrypt").textContent = output.ncryptsec;
    keyCard.hidden = true;
    form.hidden = true;
    result.hidden = false;
    result.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setError(encryptError, error && error.message ? error.message : "couldn't encrypt");
  } finally {
    busy = false;
    encryptButton.disabled = false;
    encryptButton.textContent = "encrypt nsec";
  }
}

$("useKey").addEventListener("click", useKey);
$("changeKey").addEventListener("click", changeKey);
$("newKey").addEventListener("click", resetAll);
$("encrypt").addEventListener("click", encrypt);

$("copy").addEventListener("click", async () => {
  const ok = await copyText($("resultNcrypt").textContent);
  $("copy").textContent = ok ? "copied" : "select it";
  setTimeout(() => { $("copy").textContent = "copy"; }, 1400);
});

$("share").addEventListener("click", async () => {
  const text = $("resultNcrypt").textContent;
  if (navigator.share) {
    try {
      await navigator.share({ title: "secretSecp", text });
      return;
    } catch {}
  }
  const ok = await copyText(text);
  $("share").textContent = ok ? "copied" : "select it";
  setTimeout(() => { $("share").textContent = "share"; }, 1400);
});

nsecInput.addEventListener("input", () => setError(keyError, ""));
passInput.addEventListener("input", () => setError(passError, ""));
pass2Input.addEventListener("input", () => setError(passError, ""));
nsecInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    useKey();
  }
});
pass2Input.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    encrypt();
  }
});

lognInput.addEventListener("input", updateWorkLabel);

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    ksb = Number(chip.dataset.ksb);
    document.querySelectorAll(".chip").forEach((other) => {
      other.classList.toggle("active", other === chip);
    });
    ksbText.textContent = ksbMessages[ksb];
  });
});

updateWorkLabel();
nsecInput.focus();
