#!/usr/bin/env node
import crypto from "node:crypto";

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
  return out;
}

function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 7);
}

function hchacha20(key, nonce16) {
  const state = new Uint32Array(16);
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) state[4 + i] = key.readUInt32LE(i * 4);
  for (let i = 0; i < 4; i++) state[12 + i] = nonce16.readUInt32LE(i * 4);
  for (let i = 0; i < 10; i++) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 1, 5, 9, 13);
    quarterRound(state, 2, 6, 10, 14);
    quarterRound(state, 3, 7, 11, 15);
    quarterRound(state, 0, 5, 10, 15);
    quarterRound(state, 1, 6, 11, 12);
    quarterRound(state, 2, 7, 8, 13);
    quarterRound(state, 3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(state[i], i * 4);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(state[12 + i], 16 + i * 4);
  return out;
}

function xchachaSeal(key, nonce, plaintext, aad) {
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const iv = Buffer.concat([Buffer.alloc(4), nonce.subarray(16, 24)]);
  const cipher = crypto.createCipheriv("chacha20-poly1305", subkey, iv, { authTagLength: 16 });
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

function xchachaOpen(key, nonce, sealed, aad) {
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const iv = Buffer.concat([Buffer.alloc(4), nonce.subarray(16, 24)]);
  const tag = sealed.subarray(sealed.length - 16);
  const body = sealed.subarray(0, sealed.length - 16);
  const decipher = crypto.createDecipheriv("chacha20-poly1305", subkey, iv, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

function deriveKey(passphrase, salt, logn) {
  const n = 2 ** logn;
  const maxmem = 128 * n * 8 + 16 * 1024 * 1024;
  return crypto.scryptSync(Buffer.from(passphrase.normalize("NFKC"), "utf8"), salt, 32, {
    N: n,
    r: 8,
    p: 1,
    maxmem,
  });
}

function parseSecret(input) {
  const s = String(input ?? "").trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, "hex");
  const { hrp, data } = bech32Decode(s);
  if (hrp !== "nsec") throw new Error("that isn't an nsec");
  const key = Buffer.from(convertBits(data, 5, 8, false));
  if (key.length !== 32) throw new Error("that isn't an nsec");
  return key;
}

function npubFromSecret(secret) {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(secret);
  const pub = ecdh.getPublicKey(null, "compressed");
  return bech32Encode("npub", convertBits([...pub], 8, 5, true));
}

function encrypt(input) {
  const secret = parseSecret(input.nsec);
  const logn = input.logn == null ? 16 : Number(input.logn);
  const ksb = input.ksb == null ? 0 : Number(input.ksb);
  if (!Number.isInteger(logn) || logn < 1 || logn > 20) throw new Error("logN must be between 1 and 20");
  if (![0, 1, 2].includes(ksb)) throw new Error("key security byte must be 0, 1 or 2");
  if (typeof input.pass !== "string" || input.pass === "") throw new Error("enter a passphrase");

  const salt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(24);
  const ad = Buffer.from([ksb]);
  const key = deriveKey(input.pass, salt, logn);
  const ciphertext = xchachaSeal(key, nonce, secret, ad);
  key.fill(0);

  const raw = Buffer.concat([Buffer.from([0x02, logn]), salt, nonce, ad, ciphertext]);
  if (raw.length !== 91) throw new Error("internal error: wrong ncryptsec length");
  const ncryptsec = bech32Encode("ncryptsec", convertBits([...raw], 8, 5, true));

  // Make sure the key can be read back before handing it over.
  const check = decrypt({ ncryptsec, pass: input.pass });
  if (!check.equals(secret)) throw new Error("encryption check failed");
  check.fill(0);

  const npub = npubFromSecret(secret);
  secret.fill(0);
  return { ncryptsec, npub };
}

function decrypt(input) {
  const { hrp, data } = bech32Decode(input.ncryptsec);
  if (hrp !== "ncryptsec") throw new Error("that isn't an ncryptsec");
  const raw = Buffer.from(convertBits(data, 5, 8, false));
  if (raw.length !== 91) throw new Error("that isn't an ncryptsec");
  if (raw[0] !== 0x02) throw new Error(`unsupported ncryptsec version ${raw[0]}`);
  const logn = raw[1];
  if (logn < 1 || logn > 20) throw new Error("unsupported scrypt work factor");
  if (typeof input.pass !== "string") throw new Error("enter the passphrase");
  const key = deriveKey(input.pass, raw.subarray(2, 18), logn);
  let secret;
  try {
    secret = xchachaOpen(key, raw.subarray(18, 42), raw.subarray(43), raw.subarray(42, 43));
  } catch {
    throw new Error("wrong passphrase (or damaged ncryptsec)");
  } finally {
    key.fill(0);
  }
  if (secret.length !== 32) throw new Error("not a secret key");
  return secret;
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  try {
    const input = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    const mode = process.argv[2] || "encrypt";
    let out;
    if (mode === "encrypt") {
      out = { ok: true, at: Date.now(), ...encrypt(input) };
    } else if (mode === "decrypt") {
      const secret = decrypt(input);
      const npub = npubFromSecret(secret);
      out = { ok: true, at: Date.now(), npub, nsec: secret.toString("hex") };
      secret.fill(0);
    } else if (mode === "npub") {
      const secret = parseSecret(input.nsec);
      out = { ok: true, at: Date.now(), npub: npubFromSecret(secret) };
      secret.fill(0);
    } else {
      throw new Error("unknown mode");
    }
    process.stdout.write(JSON.stringify(out));
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    process.stdout.write(JSON.stringify({ ok: false, at: Date.now(), error: message }));
  }
}

main();
