//! The security part of the VNC (RFB, RFC 6143) handshake, done in the backend.
//!
//! [`handshake`] talks to the server up to a successful SecurityResult, so VNC
//! and macOS passwords never reach the webview. The webview's noVNC client then
//! sees a server that offers RFB 3.8 with security type None ([`ClientShim`]),
//! and everything after that (ClientInit onwards) is passed through unchanged.

use std::future::Future;

use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

const NONE: u8 = 1;
const VNC_AUTH: u8 = 2;
/// Apple Remote Desktop: Diffie-Hellman, then the macOS user name and password
/// encrypted with AES-128.
const ARD: u8 = 30;

/// What the server asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// A VNC password (only the first 8 characters count).
    VncPassword,
    /// An account name and password (macOS Screen Sharing).
    Account,
}

pub struct Credentials {
    pub user: String,
    pub password: SecretString,
}

#[derive(Debug, thiserror::Error)]
pub enum RfbError {
    #[error("This isn't a VNC server, or it speaks an unsupported version ({0}).")]
    Version(String),
    #[error("The VNC server only offers sign-in methods Simple Connect doesn't support (security types {0:?}).")]
    Unsupported(Vec<u8>),
    #[error("The VNC server refused the connection: {0}")]
    Refused(String),
    #[error("Sign-in failed{}", .0.as_deref().map(|r| format!(": {r}")).unwrap_or_else(|| ". Check the password.".into()))]
    AuthFailed(Option<String>),
    #[error("Sign-in was cancelled.")]
    Cancelled,
    #[error("The VNC server sent an invalid {0}.")]
    Protocol(&'static str),
    #[error("The connection to the VNC server closed during sign-in.")]
    Io(#[from] std::io::Error),
}

async fn read_reason<S: AsyncRead + Unpin>(io: &mut S) -> Result<String, RfbError> {
    let len = io.read_u32().await? as usize;
    if len > 4096 {
        return Err(RfbError::Protocol("reason"));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(super::sanitize(&String::from_utf8_lossy(&buf), 300))
}

/// Performs the server side of the handshake. `ask` supplies credentials when
/// the server wants them; `None` cancels. Returns the security type used.
pub async fn handshake<S, F, Fut>(io: &mut S, mut ask: F) -> Result<u8, RfbError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(Need) -> Fut,
    Fut: Future<Output = Option<Credentials>>,
{
    let mut version = [0u8; 12];
    io.read_exact(&mut version).await?;
    let text = String::from_utf8_lossy(&version).into_owned();
    let minor = text
        .strip_prefix("RFB 003.")
        .and_then(|r| r.strip_suffix('\n'))
        .and_then(|m| m.parse::<u16>().ok())
        .ok_or_else(|| RfbError::Version(super::sanitize(&text, 12)))?;
    // 3.889 is Apple's 3.8; unknown minors fall back to 3.3 (RFC 6143 §7.1.1).
    let minor = match minor {
        8.. => 8,
        7 => 7,
        _ => 3,
    };
    io.write_all(format!("RFB 003.00{minor}\n").as_bytes()).await?;

    let chosen = if minor == 3 {
        match io.read_u32().await? {
            0 => return Err(RfbError::Refused(read_reason(io).await?)),
            t @ (1 | 2) => t as u8,
            t => return Err(RfbError::Unsupported(vec![u8::try_from(t).unwrap_or(u8::MAX)])),
        }
    } else {
        let n = io.read_u8().await?;
        if n == 0 {
            return Err(RfbError::Refused(read_reason(io).await?));
        }
        let mut types = vec![0u8; n as usize];
        io.read_exact(&mut types).await?;
        let pick = [NONE, ARD, VNC_AUTH].into_iter().find(|t| types.contains(t)).ok_or(RfbError::Unsupported(types))?;
        io.write_u8(pick).await?;
        pick
    };

    match chosen {
        VNC_AUTH => {
            let mut challenge = [0u8; 16];
            io.read_exact(&mut challenge).await?;
            let creds = ask(Need::VncPassword).await.ok_or(RfbError::Cancelled)?;
            io.write_all(&vnc_response(&creds.password, &challenge)).await?;
        }
        ARD => {
            let generator = io.read_u16().await?;
            let len = io.read_u16().await? as usize;
            if !(16..=512).contains(&len) {
                return Err(RfbError::Protocol("Apple key exchange"));
            }
            let mut prime = vec![0u8; len];
            io.read_exact(&mut prime).await?;
            let mut server_key = vec![0u8; len];
            io.read_exact(&mut server_key).await?;
            let creds = ask(Need::Account).await.ok_or(RfbError::Cancelled)?;
            let reply = ard_response(generator, &prime, &server_key, &creds).map_err(|()| RfbError::Protocol("Apple key exchange"))?;
            io.write_all(&reply).await?;
        }
        _ => {}
    }
    io.flush().await?;

    // RFB 3.3 and 3.7 send no SecurityResult for None.
    if chosen == NONE && minor < 8 {
        return Ok(chosen);
    }
    match io.read_u32().await? {
        0 => Ok(chosen),
        _ if minor >= 8 => Err(RfbError::AuthFailed(Some(read_reason(io).await?).filter(|r| !r.is_empty()))),
        _ => Err(RfbError::AuthFailed(None)),
    }
}

/// VNC authentication: the challenge encrypted with DES, keyed by the first 8
/// password bytes with each byte's bits reversed (a quirk of the original code).
fn vnc_response(password: &SecretString, challenge: &[u8; 16]) -> [u8; 16] {
    use des::Des;
    use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let mut key = Zeroizing::new([0u8; 8]);
    for (k, b) in key.iter_mut().zip(password.expose_secret().bytes()) {
        *k = b.reverse_bits();
    }
    let cipher = Des::new(GenericArray::from_slice(&key[..]));
    let mut out = *challenge;
    for block in out.as_chunks_mut::<8>().0 {
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }
    out
}

fn left_pad(mut v: Vec<u8>, len: usize) -> Vec<u8> {
    if v.len() < len {
        let mut padded = vec![0u8; len - v.len()];
        padded.append(&mut v);
        padded
    } else {
        v
    }
}

/// Apple Remote Desktop authentication (as implemented by noVNC and
/// libvncclient): a DH key agreement with the server's parameters, MD5 of the
/// shared secret as an AES-128 key, and the encrypted 128-byte credential block
/// followed by our public key.
fn ard_response(generator: u16, prime: &[u8], server_key: &[u8], creds: &Credentials) -> Result<Vec<u8>, ()> {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    use md5::{Digest, Md5};
    use num_bigint::BigUint;

    let len = prime.len();
    let p = BigUint::from_bytes_be(prime);
    let g = BigUint::from(generator);
    let server = BigUint::from_bytes_be(server_key);
    let one = BigUint::from(1u8);
    if p <= one || server <= one || server >= p {
        return Err(());
    }
    let mut private = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut private).map_err(drop)?;
    let x = BigUint::from_bytes_be(&private);
    let public = left_pad(g.modpow(&x, &p).to_bytes_be(), len);
    let shared = Zeroizing::new(left_pad(server.modpow(&x, &p).to_bytes_be(), len));
    let key = Md5::digest(&shared[..]);

    let mut block = Zeroizing::new([0u8; 128]);
    getrandom::fill(&mut block[..]).map_err(drop)?;
    let user = creds.user.as_bytes();
    let pass = creds.password.expose_secret().as_bytes();
    let (ul, pl) = (user.len().min(63), pass.len().min(63));
    block[..ul].copy_from_slice(&user[..ul]);
    block[ul] = 0;
    block[64..64 + pl].copy_from_slice(&pass[..pl]);
    block[64 + pl] = 0;
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    for chunk in block.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    let mut out = Vec::with_capacity(128 + len);
    out.extend_from_slice(&block[..]);
    out.extend_from_slice(&public);
    Ok(out)
}

/// What noVNC is told: RFB 3.8, security type None.
pub const HELLO: &[u8] = b"RFB 003.008\n";

/// Plays the server's side of the security handshake towards noVNC, which
/// writes 12 bytes of version and then 1 byte selecting the security type.
#[derive(Default)]
pub struct ClientShim {
    seen: usize,
}

impl ClientShim {
    /// Returns the reply for noVNC and the bytes to pass on to the server.
    pub fn feed<'a>(&mut self, data: &'a [u8]) -> (Vec<u8>, &'a [u8]) {
        const VERSION: usize = 12;
        const DONE: usize = VERSION + 1;
        let take = (DONE - self.seen.min(DONE)).min(data.len());
        let before = self.seen;
        self.seen += take;
        let mut reply = Vec::new();
        if before < VERSION && self.seen >= VERSION {
            reply.extend_from_slice(&[1, NONE]);
        }
        if before < DONE && self.seen >= DONE {
            reply.extend_from_slice(&0u32.to_be_bytes());
        }
        (reply, &data[take..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn creds(user: &str, pw: &str) -> Credentials {
        Credentials { user: user.into(), password: SecretString::from(pw.to_owned()) }
    }

    /// A scripted server: writes `script` in order, and records what the client sends.
    async fn run(server_bytes: Vec<u8>, answer: Option<(&'static str, &'static str)>) -> (Result<u8, RfbError>, Vec<u8>, Vec<Need>) {
        let (mut client, mut server) = duplex(1 << 16);
        server.write_all(&server_bytes).await.unwrap();
        let mut asked = Vec::new();
        let r = handshake(&mut client, |need| {
            asked.push(need);
            let a = answer.map(|(u, p)| creds(u, p));
            async move { a }
        })
        .await;
        drop(client);
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        (r, sent, asked)
    }

    #[tokio::test]
    async fn none_on_38_and_33() {
        let mut s = b"RFB 003.008\n".to_vec();
        s.extend([2, VNC_AUTH, NONE]);
        s.extend(0u32.to_be_bytes());
        let (r, sent, asked) = run(s, None).await;
        assert_eq!(r.unwrap(), NONE);
        assert_eq!(sent, b"RFB 003.008\n\x01", "None is preferred, nothing asked");
        assert!(asked.is_empty());

        // 3.3: the server picks; no SecurityResult for None.
        let mut s = b"RFB 003.003\n".to_vec();
        s.extend(1u32.to_be_bytes());
        let (r, sent, _) = run(s, None).await;
        assert_eq!((r.unwrap(), sent.as_slice()), (NONE, &b"RFB 003.003\n"[..]));
    }

    #[tokio::test]
    async fn apple_version_is_treated_as_38() {
        let mut s = b"RFB 003.889\n".to_vec();
        s.extend([1, NONE]);
        s.extend(0u32.to_be_bytes());
        let (r, sent, _) = run(s, None).await;
        assert!(r.is_ok());
        assert!(sent.starts_with(b"RFB 003.008\n"));
    }

    #[tokio::test]
    async fn vnc_auth_and_failure_reason() {
        let challenge = [7u8; 16];
        let mut s = b"RFB 003.008\n".to_vec();
        s.extend([1, VNC_AUTH]);
        s.extend(challenge);
        s.extend(1u32.to_be_bytes());
        s.extend(14u32.to_be_bytes());
        s.extend(b"Wrong password");
        let (r, sent, asked) = run(s, Some(("", "secret"))).await;
        assert!(matches!(r, Err(RfbError::AuthFailed(Some(ref m))) if m == "Wrong password"), "{r:?}");
        assert_eq!(asked, [Need::VncPassword]);
        assert_eq!(sent.len(), 12 + 1 + 16);
        assert_eq!(&sent[13..], vnc_response(&SecretString::from("secret".to_owned()), &challenge));
    }

    /// Reference computed independently with `openssl enc -des-ecb -K 0e86ceceeef64e26`
    /// ("password" with each byte's bits reversed) over the bytes 00..0f.
    #[test]
    fn vnc_des_matches_reference() {
        let challenge: [u8; 16] = std::array::from_fn(|i| i as u8);
        let got = vnc_response(&SecretString::from("password".to_owned()), &challenge);
        let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "b866924125c8eebb9debc1db61c538e2");
        let longer = vnc_response(&SecretString::from("password-longer-than-8".to_owned()), &challenge);
        assert_eq!(got, longer, "only the first 8 characters count");
    }

    #[tokio::test]
    async fn ard_sends_encrypted_block_and_public_key() {
        // A small safe prime keeps the test fast; real servers send 128 bytes.
        let prime = 0xffff_fffb_u32.to_be_bytes().repeat(4); // 16-byte modulus
        let mut s = b"RFB 003.889\n".to_vec();
        s.extend([2, VNC_AUTH, ARD]);
        s.extend(2u16.to_be_bytes());
        s.extend(16u16.to_be_bytes());
        s.extend(&prime);
        s.extend([0u8; 15].iter().copied().chain([5]));
        s.extend(0u32.to_be_bytes());
        let (r, sent, asked) = run(s, Some(("alice", "pw"))).await;
        assert_eq!(r.unwrap(), ARD, "ARD is preferred over the weaker VNC password");
        assert_eq!(asked, [Need::Account]);
        assert_eq!(sent.len(), 12 + 1 + 128 + 16);
    }

    #[tokio::test]
    async fn rejects_garbage() {
        let (r, ..) = run(b"SSH-2.0-Open".to_vec(), None).await;
        assert!(matches!(r, Err(RfbError::Version(_))));
        let mut s = b"RFB 003.008\n".to_vec();
        s.extend([2, 18, 19]); // TLS, VeNCrypt
        let (r, ..) = run(s, None).await;
        assert!(matches!(r, Err(RfbError::Unsupported(ref t)) if t == &[18, 19]));
        let mut s = b"RFB 003.008\n".to_vec();
        s.extend([0]);
        s.extend(9u32.to_be_bytes());
        s.extend(b"Too many!");
        let (r, ..) = run(s, None).await;
        assert!(matches!(r, Err(RfbError::Refused(ref m)) if m == "Too many!"));
        let mut s = b"RFB 003.008\n".to_vec();
        s.extend([1, VNC_AUTH]);
        s.extend([0u8; 16]);
        let (r, ..) = run(s, None).await;
        assert!(matches!(r, Err(RfbError::Cancelled)));
    }

    #[test]
    fn shim_answers_novnc() {
        let mut shim = ClientShim::default();
        let (reply, pass) = shim.feed(b"RFB 003.008\n");
        assert_eq!((reply.as_slice(), pass), (&[1, NONE][..], &[][..]));
        let (reply, pass) = shim.feed(&[NONE, 1, 9, 9]); // type, then ClientInit and more
        assert_eq!((reply.as_slice(), pass), (&[0, 0, 0, 0][..], &[1, 9, 9][..]));
        let (reply, pass) = shim.feed(&[3]);
        assert_eq!((reply.len(), pass), (0, &[3][..]));

        // Everything in one write.
        let mut shim = ClientShim::default();
        let mut all = b"RFB 003.008\n".to_vec();
        all.extend([NONE, 1]);
        let (reply, pass) = shim.feed(&all);
        assert_eq!((reply.as_slice(), pass), (&[1, NONE, 0, 0, 0, 0][..], &[1][..]));
    }
}
