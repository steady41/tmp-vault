/* Client-side AES-GCM primitives. The plaintext secret and the 256-bit key
 * never leave this browser. Only the ciphertext is sent to the server; the key
 * travels to the recipient inside the URL fragment (window.location.hash). */

function bytesToB64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBytes(b64) {
  const s = b64.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function encryptSecret(plaintext) {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, new TextEncoder().encode(plaintext))
  );
  const blob = new Uint8Array(iv.length + encrypted.length);
  blob.set(iv, 0);
  blob.set(encrypted, iv.length);
  return { ciphertext: bytesToB64url(blob), keyB64: bytesToB64url(key) };
}

async function decryptSecret(ciphertextB64, keyB64) {
  const blob = b64urlToBytes(ciphertextB64);
  const iv = blob.slice(0, 12);
  const data = blob.slice(12);
  const cryptoKey = await crypto.subtle.importKey("raw", b64urlToBytes(keyB64), { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, data);
  return new TextDecoder().decode(plain);
}
