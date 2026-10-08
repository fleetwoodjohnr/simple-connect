// Human names for negotiated algorithms (raw names stay visible in the details).

const CIPHERS: Record<string, string> = {
  "chacha20-poly1305@openssh.com": "ChaCha20-Poly1305",
  "aes256-gcm@openssh.com": "AES-256-GCM",
  "aes128-gcm@openssh.com": "AES-128-GCM",
  "aes256-ctr": "AES-256-CTR",
  "aes192-ctr": "AES-192-CTR",
  "aes128-ctr": "AES-128-CTR",
};
const HOST_KEYS: Record<string, string> = {
  "ssh-ed25519": "Ed25519",
  "sk-ssh-ed25519@openssh.com": "Ed25519 (security key)",
  "ecdsa-sha2-nistp256": "ECDSA P-256",
  "ecdsa-sha2-nistp384": "ECDSA P-384",
  "ecdsa-sha2-nistp521": "ECDSA P-521",
  "rsa-sha2-512": "RSA (SHA-512)",
  "rsa-sha2-256": "RSA (SHA-256)",
  "ssh-rsa": "RSA (SHA-1, legacy)",
};
const KEX: Record<string, string> = {
  "mlkem768x25519-sha256": "ML-KEM-768 + X25519 (post-quantum hybrid)",
  "sntrup761x25519-sha512": "NTRU Prime + X25519 (post-quantum hybrid)",
  "sntrup761x25519-sha512@openssh.com": "NTRU Prime + X25519 (post-quantum hybrid)",
  "curve25519-sha256": "Curve25519",
  "curve25519-sha256@libssh.org": "Curve25519",
};
const AUTH: Record<string, string> = {
  publickey: "Public key",
  password: "Password",
  "keyboard-interactive": "Keyboard-interactive",
  "gssapi-with-mic": "Kerberos (GSSAPI)",
};

const pick = (map: Record<string, string>) => (raw: string | null | undefined) => (raw ? (map[raw] ?? raw) : "Unknown");
export const cipherName = pick(CIPHERS);
export const hostKeyName = pick(HOST_KEYS);
export const kexName = pick(KEX);
export const authName = pick(AUTH);
export const keyTypeName = (t: string) => HOST_KEYS[t] ?? t;

/** Weak choices that only appear with the per-connection legacy option. */
export const isLegacy = (raw: string | null | undefined) => !!raw && /cbc|sha1|ssh-rsa$|group1-|group14-sha1/.test(raw);
