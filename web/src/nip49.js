import { scryptAsync } from "@noble/hashes/scrypt.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GENERATOR[i];
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function createChecksum(hrp, data) {
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const out = [];
  for (let i = 0; i < 6; i++) out.push((mod >>> (5 * (5 - i))) & 31);
  return out;
}

function bech32Encode(hrp, data) {
  const combined = [...data, ...createChecksum(hrp, data)];
  return hrp + "1" + combined.map((d) => CHARSET[d]).join("");
}

function bech32Decode(text) {
  const s = String(text ?? "").trim();
  if (s.length < 8 || s.length > 1000) throw new Error("not a bech32 key");
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error("not a bech32 key (mixed case)");
  const lower = s.toLowerCase();
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || pos + 7 > lower.length) throw new Error("not a bech32 key");
  const hrp = lower.slice(0, pos);
  const data = [];
  for (const c of lower.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v === -1) throw new Error("not a bech32 key (bad character)");
    data.push(v);
  }
  if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error("not a bech32 key (bad checksum)");
  return { hrp, data: data.slice(0, -6) };
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const maxv = (1 << to) - 1;
  const out = [];
  for (const value of data) {
    if (value < 0 || value >> from) throw new Error("bad bech32 data");
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    throw new Error("bad bech32 padding");
  }
  return Uint8Array.from(out);
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function randomBytes(n) {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function wipe(bytes) {
  if (bytes) bytes.fill(0);
}

export function parseSecret(input) {
  const s = String(input ?? "").trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return fromHex(s);
  const { hrp, data } = bech32Decode(s);
  if (hrp !== "nsec") throw new Error("that isn't an nsec");
  const key = convertBits(data, 5, 8, false);
  if (key.length !== 32) throw new Error("that isn't an nsec");
  return key;
}

export function npubFromSecret(secret) {
  const pub = secp256k1.getPublicKey(secret, true);
  return bech32Encode("npub", convertBits(pub, 8, 5, true));
}

export function npubFromInput(input) {
  const secret = parseSecret(input);
  try {
    return npubFromSecret(secret);
  } finally {
    wipe(secret);
  }
}

async function deriveKey(passphrase, salt, logn, onProgress) {
  const n = 2 ** logn;
  return scryptAsync(new TextEncoder().encode(passphrase.normalize("NFKC")), salt, {
    N: n,
    r: 8,
    p: 1,
    dkLen: 32,
    maxmem: 128 * n * 8 + 16 * 1024 * 1024,
    asyncTick: 10,
    onProgress,
  });
}

export async function encryptNsec(input, onProgress) {
  const secret = parseSecret(input.nsec);
  const logn = input.logn == null ? 16 : Number(input.logn);
  const ksb = input.ksb == null ? 0 : Number(input.ksb);
  if (!Number.isInteger(logn) || logn < 1 || logn > 20) throw new Error("logN must be between 1 and 20");
  if (![0, 1, 2].includes(ksb)) throw new Error("key security byte must be 0, 1 or 2");
  if (typeof input.pass !== "string" || input.pass === "") throw new Error("enter a passphrase");

  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const ad = Uint8Array.of(ksb);
  const key = await deriveKey(input.pass, salt, logn, onProgress);
  const ciphertext = xchacha20poly1305(key, nonce, ad).encrypt(secret);
  wipe(key);

  const raw = new Uint8Array(91);
  raw[0] = 0x02;
  raw[1] = logn;
  raw.set(salt, 2);
  raw.set(nonce, 18);
  raw.set(ad, 42);
  raw.set(ciphertext, 43);
  const ncryptsec = bech32Encode("ncryptsec", convertBits(raw, 8, 5, true));

  const check = await decryptNcryptsec({ ncryptsec, pass: input.pass });
  const same = check.length === secret.length && check.every((b, i) => b === secret[i]);
  wipe(check);
  if (!same) throw new Error("encryption check failed");

  const npub = npubFromSecret(secret);
  wipe(secret);
  return { ncryptsec, npub };
}

export async function decryptNcryptsec(input) {
  const { hrp, data } = bech32Decode(input.ncryptsec);
  if (hrp !== "ncryptsec") throw new Error("that isn't an ncryptsec");
  const raw = convertBits(data, 5, 8, false);
  if (raw.length !== 91) throw new Error("that isn't an ncryptsec");
  if (raw[0] !== 0x02) throw new Error(`unsupported ncryptsec version ${raw[0]}`);
  const logn = raw[1];
  if (logn < 1 || logn > 20) throw new Error("unsupported scrypt work factor");
  if (typeof input.pass !== "string") throw new Error("enter the passphrase");
  const key = await deriveKey(input.pass, raw.subarray(2, 18), logn);
  let secret;
  try {
    secret = xchacha20poly1305(key, raw.subarray(18, 42), raw.subarray(42, 43)).decrypt(raw.subarray(43));
  } catch {
    throw new Error("wrong passphrase (or damaged ncryptsec)");
  } finally {
    wipe(key);
  }
  if (secret.length !== 32) throw new Error("not a secret key");
  return secret;
}

export { toHex, fromHex, wipe };
