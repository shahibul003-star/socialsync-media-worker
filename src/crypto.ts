const encoder = new TextEncoder();
export async function verify(value: string, signature: string, secret: string) {
  if (secret.length < 32 || !/^[a-f0-9]{64}$/i.test(signature)) return false;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const bytes = Uint8Array.from(signature.match(/../g)!, (v) => parseInt(v, 16));
  return crypto.subtle.verify("HMAC", key, bytes, encoder.encode(value));
}
