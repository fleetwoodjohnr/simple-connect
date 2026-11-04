//! RDP through the SSH forward, decoded in the backend with IronRDP. The webview
//! only receives changed rectangles of pixels and sends typed input events.
//!
//! Security: the TCP endpoint is the remote computer's own loopback, reached
//! through the SSH connection whose host key was verified. So the RDP server's
//! (usually self-signed) certificate isn't checked against a CA; the TLS
//! handshake still proves the server holds the certificate's key, and NLA
//! (CredSSP) binds the credentials to that key. Only TLS and NLA are offered,
//! never the legacy RC4 "RDP security", and the negotiation itself runs inside
//! SSH, so it can't be downgraded on the network. No audio, drive, printer or
//! smart-card redirection is offered; the clipboard carries text only.

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironrdp_cliprdr::CliprdrClient;
use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse, FormatDataRequest,
    FormatDataResponse, LockDataId, OwnedFormatDataResponse,
};
use ironrdp_connector::connection_activation::ConnectionActivationState;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{ConnectionResult, ConnectorErrorKind, ConnectorResult, Credentials, DesktopSize, ServerName};
use ironrdp_core::WriteBuf;
use ironrdp_displaycontrol::client::DisplayControlClient;
use ironrdp_displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, fast_path};
use ironrdp_tokio::{FramedWrite, TokioFramed, single_sequence_step_read, split_tokio_framed};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::rustls;

use super::{DesktopError, Quality};

/// Messages to the webview (src/desktop/RdpViewer.tsx), little-endian.
const RECT: u8 = 1;
const SIZE: u8 = 2;
const CURSOR: u8 = 3;
const CURSOR_HIDDEN: u8 = 4;
const CURSOR_DEFAULT: u8 = 5;
const CLIPBOARD: u8 = 6;

/// Rectangles waiting for the webview are merged beyond this many.
const MAX_RECTS: usize = 16;
/// Pixels are held back while the webview is this far behind.
const BEHIND: usize = 8 * 1024 * 1024;
const MAX_CLIPBOARD: usize = 1024 * 1024;

/// Input from the webview. Positions are remote desktop pixels.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum Input {
    Key { scancode: u8, extended: bool, down: bool },
    Unicode { ch: u32, down: bool },
    Mouse { x: u16, y: u16 },
    Button { button: Button, down: bool },
    Wheel { delta: i16, horizontal: bool },
    ReleaseAll,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Button {
    Left,
    Middle,
    Right,
    X1,
    X2,
}

pub enum Cmd {
    Input(Vec<Input>),
    Resize(u16, u16),
    /// Offer this text as the clipboard to the remote computer.
    Clipboard(String),
}

pub struct Params {
    pub width: u16,
    pub height: u16,
    pub quality: Quality,
    /// For CredSSP (the SSH host name).
    pub server_name: String,
}

type Stream = Box<dyn AsyncReadWrite + Unpin + Send + Sync>;
trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// What a session thread needs from the application.
pub enum Event {
    /// The server answered; sign-in needs this account's password (`None` cancels).
    NeedPassword(oneshot::Sender<Option<SecretString>>),
    /// Signed in. `latency`: the first round trip, for picking image quality.
    Connected { latency: Duration },
}

pub type Sink = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// Runs one RDP connection on its own thread, from starting the `ssh -W`
/// forward (`program` with `args`) to the end of the session.
///
/// IronRDP's futures can't be proven `Send` (its framing traits use
/// lifetime-generic futures), so like IronRDP's own client this runs them with
/// `block_on` on a dedicated thread. Dropping the returned receiver ends it.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    program: PathBuf,
    args: Vec<OsString>,
    params: Params,
    account: String,
    sink: Sink,
    behind: Arc<dyn Fn() -> usize + Send + Sync>,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    events: mpsc::UnboundedSender<Event>,
) -> oneshot::Receiver<Result<(), DesktopError>> {
    let (mut done, result) = oneshot::channel();
    let thread = std::thread::Builder::new().name("rdp-session".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                return drop(done.send(Err(DesktopError::new("protocol", "Remote Desktop couldn't start.").with_details(e.to_string()))));
            }
        };
        rt.block_on(async {
            let work = session(program, args, params, account, sink, behind, &mut cmds, events);
            let r = tokio::select! {
                r = work => Some(r),
                () = done.closed() => None,
            };
            if let Some(r) = r {
                let _ = done.send(r);
            }
        });
    });
    if let Err(e) = thread {
        tracing::error!("could not start an RDP thread: {e}");
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn session(
    program: PathBuf,
    args: Vec<OsString>,
    params: Params,
    account: String,
    sink: Sink,
    behind: Arc<dyn Fn() -> usize + Send + Sync>,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    events: mpsc::UnboundedSender<Event>,
) -> Result<(), DesktopError> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| DesktopError::new("server", "OpenSSH could not be started.").with_details(e.to_string()))?;
    let (Some(reader), Some(writer)) = (child.stdout.take(), child.stdin.take()) else {
        return Err(DesktopError::new("server", "OpenSSH could not be started."));
    };
    let begun = begin(tokio::io::join(reader, writer), &params).await?;
    let latency = begun.latency;
    let (reply, password) = oneshot::channel();
    events.send(Event::NeedPassword(reply)).map_err(|_| DesktopError::new("cancelled", "Sign-in was cancelled."))?;
    let password = password.await.ok().flatten().ok_or_else(|| DesktopError::new("cancelled", "Sign-in was cancelled."))?;
    let connected = finish(begun, &account, &password).await?;
    drop(password);
    let _ = events.send(Event::Connected { latency });
    run(connected, &*sink, cmds, &*behind).await
}

/// After the X.224 negotiation: the server answered and accepts TLS or NLA.
pub struct Begun {
    connector: ironrdp_connector::ClientConnector,
    framed: TokioFramed<Stream>,
    upgrade: ironrdp_tokio::ShouldUpgrade,
    server_name: String,
    /// The first round trip, for picking image quality.
    pub latency: Duration,
}

pub struct Connected {
    framed: TokioFramed<Stream>,
    result: ConnectionResult,
}

/// `DOMAIN\user` → (domain, user). `user@domain` is passed on as is.
fn split_account(account: &str) -> (Option<String>, String) {
    match account.split_once('\\') {
        Some((d, u)) => (Some(d.to_owned()), u.to_owned()),
        None => (None, account.to_owned()),
    }
}

fn performance(q: Quality) -> PerformanceFlags {
    let lean = PerformanceFlags::DISABLE_WALLPAPER | PerformanceFlags::DISABLE_FULLWINDOWDRAG | PerformanceFlags::DISABLE_MENUANIMATIONS;
    match q {
        Quality::High => PerformanceFlags::ENABLE_FONT_SMOOTHING | PerformanceFlags::ENABLE_DESKTOP_COMPOSITION,
        Quality::Auto | Quality::Balanced => lean | PerformanceFlags::ENABLE_FONT_SMOOTHING,
        Quality::Low => lean | PerformanceFlags::DISABLE_THEMING | PerformanceFlags::DISABLE_CURSOR_SHADOW,
    }
}

/// The credentials are filled in by [`finish`], after the server has answered.
fn config(p: &Params) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        desktop_size: DesktopSize { width: p.width, height: p.height },
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: true,
        credentials: Credentials::UsernamePassword { username: String::new(), password: String::new() },
        domain: None,
        client_build: 0,
        client_name: "simple-connect".into(),
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        ime_file_name: String::new(),
        bitmap: Some(ironrdp_connector::BitmapConfig {
            lossy_compression: true,
            color_depth: 32,
            codecs: ironrdp_pdu::rdp::capability_sets::client_codecs_capabilities(&[]).unwrap_or_default(),
        }),
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: true,
        enable_audio_playback: false,
        performance_flags: performance(p.quality),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: Some(CompressionType::K64),
        enable_server_pointer: true,
        pointer_software_rendering: false,
        multitransport_flags: None,
    }
}

/// CredSSP may ask to reach a Kerberos KDC; Simple Connect never makes
/// network connections of its own, so only NTLM (local and domain accounts
/// by password) is available.
struct NoNetwork;

impl ironrdp_tokio::NetworkClient for NoNetwork {
    // A concrete future with no borrowed lifetimes, so the connection future is
    // provably `Send` (an `async fn` here trips rustc's higher-ranked checks).
    #[allow(refining_impl_trait)]
    fn send(&mut self, _: &NetworkRequest) -> std::future::Ready<ConnectorResult<Vec<u8>>> {
        std::future::ready(Err(ironrdp_connector::general_err!("Kerberos is not supported")))
    }
}

/// Accepts the server's certificate without a CA (see the module comment) but
/// checks the handshake signatures, so the server must hold the certificate's key.
#[derive(Debug)]
struct LoopbackVerifier(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for LoopbackVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS without session resumption (CredSSP doesn't support it) and without
/// key logging. Returns the server's public key for CredSSP.
async fn tls<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> std::io::Result<(tokio_rustls::client::TlsStream<S>, Vec<u8>)> {
    use x509_cert::der::Decode as _;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(LoopbackVerifier(provider)))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    let name = rustls::pki_types::ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream).await?;
    stream.flush().await?;
    let cert =
        stream.get_ref().1.peer_certificates().and_then(|c| c.first()).ok_or_else(|| std::io::Error::other("no server certificate"))?;
    let cert = x509_cert::Certificate::from_der(cert).map_err(std::io::Error::other)?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| std::io::Error::other("bad server key"))?;
    Ok((stream, key.to_vec()))
}

fn connector_error(e: ironrdp_connector::ConnectorError) -> DesktopError {
    let details = format!("{e:#}");
    let legacy = || {
        DesktopError::new(
            "unsupported",
            "This Remote Desktop server only offers outdated encryption. Turn on TLS or Network Level Authentication on it.",
        )
        .with_details(details.clone())
    };
    match e.kind() {
        // We offer TLS and NLA only; a server answering with RDP security is refused.
        ConnectorErrorKind::Reason(r) if r.contains("server selected") || r.contains("standard RDP security") => legacy(),
        ConnectorErrorKind::Credssp(_) | ConnectorErrorKind::AccessDenied => {
            DesktopError::new("auth", "The user name or password was rejected.").with_details(details)
        }
        ConnectorErrorKind::Negotiation(f) if f.code() == ironrdp_pdu::nego::FailureCode::SSL_NOT_ALLOWED_BY_SERVER => legacy(),
        _ => DesktopError::new("protocol", "The Remote Desktop connection failed.").with_details(details),
    }
}

/// Starts the RDP connection over `stream` (the SSH forward): the security
/// negotiation, before any credentials are needed.
pub async fn begin<S>(stream: S, p: &Params) -> Result<Begun, DesktopError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let drdynvc = ironrdp_dvc::DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new())));
    let mut connector = ironrdp_connector::ClientConnector::new(config(p), client_addr).with_static_channel(drdynvc);
    connector.attach_static_channel(CliprdrClient::new(Box::new(Clipboard::default())));
    let stream: Stream = Box::new(stream);
    let mut framed = TokioFramed::new(stream);
    let started = Instant::now();
    let upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await.map_err(connector_error)?;
    Ok(Begun { connector, framed, upgrade, server_name: p.server_name.clone(), latency: started.elapsed() })
}

/// TLS, sign-in (NLA when the server supports it) and the rest of the connection sequence.
pub async fn finish(b: Begun, account: &str, password: &SecretString) -> Result<Connected, DesktopError> {
    let Begun { mut connector, framed, upgrade, server_name, .. } = b;
    let (domain, username) = split_account(account);
    connector.config.credentials = Credentials::UsernamePassword { username, password: password.expose_secret().to_owned() };
    connector.config.domain = domain;
    let (stream, leftover) = framed.into_inner();
    let (stream, server_key) = tls(stream)
        .await
        .map_err(|e| DesktopError::new("protocol", "The secure connection to Remote Desktop failed.").with_details(e.to_string()))?;
    let upgraded = ironrdp_tokio::mark_as_upgraded(upgrade, &mut connector);
    let stream: Stream = Box::new(stream);
    let mut framed = TokioFramed::new_with_leftover(stream, leftover);
    let result =
        ironrdp_tokio::connect_finalize(upgraded, connector, &mut framed, &mut NoNetwork, ServerName::new(server_name), server_key, None)
            .await
            .map_err(connector_error)?;
    Ok(Connected { framed, result })
}

// ---- clipboard ----------------------------------------------------------------

#[derive(Debug)]
enum ClipEvent {
    /// Send our format list (when the channel is ready or the server asks).
    Announce,
    /// The remote clipboard now holds text: fetch it.
    RemoteText,
    /// The server wants our text.
    Requested(ClipboardFormatId),
    Received(String),
}

/// Text-only clipboard. Callbacks only queue events; the session loop acts on them.
#[derive(Debug, Default)]
struct Clipboard {
    tx: Option<mpsc::UnboundedSender<ClipEvent>>,
    pending: Vec<ClipEvent>,
}

ironrdp_core::impl_as_any!(Clipboard);

impl Clipboard {
    fn send(&mut self, e: ClipEvent) {
        match &self.tx {
            Some(tx) => drop(tx.send(e)),
            None => self.pending.push(e),
        }
    }
}

impl CliprdrBackend for Clipboard {
    fn temporary_directory(&self) -> &str {
        ".cliprdr"
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }
    fn on_ready(&mut self) {
        self.send(ClipEvent::Announce);
    }
    fn on_request_format_list(&mut self) {
        self.send(ClipEvent::Announce);
    }
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        if formats.iter().any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT) {
            self.send(ClipEvent::RemoteText);
        }
    }
    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.send(ClipEvent::Requested(request.format));
    }
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if !response.is_error()
            && let Ok(text) = response.to_unicode_string()
        {
            self.send(ClipEvent::Received(text));
        }
    }
    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}

// ---- the session ----------------------------------------------------------------

/// Changed areas not yet sent to the webview.
#[derive(Default)]
struct Dirty(Vec<InclusiveRectangle>);

impl Dirty {
    fn add(&mut self, r: InclusiveRectangle) {
        self.0.push(r);
        if self.0.len() > MAX_RECTS {
            let all = self.0.drain(..).reduce(|a, b| InclusiveRectangle {
                left: a.left.min(b.left),
                top: a.top.min(b.top),
                right: a.right.max(b.right),
                bottom: a.bottom.max(b.bottom),
            });
            self.0.extend(all);
        }
    }
}

/// One rectangle as RGBA with opaque alpha.
fn encode_rect(image: &DecodedImage, r: &InclusiveRectangle) -> Option<Vec<u8>> {
    let (iw, ih) = (image.width(), image.height());
    if r.left >= iw || r.top >= ih {
        return None;
    }
    let (right, bottom) = (r.right.min(iw - 1), r.bottom.min(ih - 1));
    if right < r.left || bottom < r.top {
        return None;
    }
    let (w, h) = (usize::from(right - r.left + 1), usize::from(bottom - r.top + 1));
    let stride = image.stride();
    let data = image.data();
    let mut out = Vec::with_capacity(9 + w * h * 4);
    out.push(RECT);
    for v in [r.left, r.top, right - r.left + 1, bottom - r.top + 1] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for y in usize::from(r.top)..=usize::from(bottom) {
        let start = y * stride + usize::from(r.left) * 4;
        let row = data.get(start..start + w * 4)?;
        out.extend(row.as_chunks::<4>().0.iter().flat_map(|p| [p[0], p[1], p[2], 0xff]));
    }
    Some(out)
}

fn size_message(image: &DecodedImage) -> Vec<u8> {
    let mut m = vec![SIZE];
    m.extend_from_slice(&image.width().to_le_bytes());
    m.extend_from_slice(&image.height().to_le_bytes());
    m
}

fn full(image: &DecodedImage) -> InclusiveRectangle {
    InclusiveRectangle { left: 0, top: 0, right: image.width().saturating_sub(1), bottom: image.height().saturating_sub(1) }
}

fn operations(input: Vec<Input>, size: (u16, u16)) -> Vec<Operation> {
    input
        .into_iter()
        .filter_map(|i| {
            Some(match i {
                Input::Key { scancode, extended, down } => {
                    let sc = Scancode::from_u8(extended, scancode);
                    if down { Operation::KeyPressed(sc) } else { Operation::KeyReleased(sc) }
                }
                Input::Unicode { ch, down } => {
                    let c = char::from_u32(ch).filter(|c| !c.is_control())?;
                    if down { Operation::UnicodeKeyPressed(c) } else { Operation::UnicodeKeyReleased(c) }
                }
                Input::Mouse { x, y } => {
                    Operation::MouseMove(MousePosition { x: x.min(size.0.saturating_sub(1)), y: y.min(size.1.saturating_sub(1)) })
                }
                Input::Button { button, down } => {
                    let b = match button {
                        Button::Left => MouseButton::Left,
                        Button::Middle => MouseButton::Middle,
                        Button::Right => MouseButton::Right,
                        Button::X1 => MouseButton::X1,
                        Button::X2 => MouseButton::X2,
                    };
                    if down { Operation::MouseButtonPressed(b) } else { Operation::MouseButtonReleased(b) }
                }
                Input::Wheel { delta, horizontal } => {
                    Operation::WheelRotations(WheelRotations { is_vertical: !horizontal, rotation_units: delta.clamp(-1200, 1200) })
                }
                Input::ReleaseAll => return None,
            })
        })
        .collect()
}

/// xrdp (when resizing) sends a Deactivate All PDU that is only a Share Control
/// Header, without the shareId and source descriptor [MS-RDPBCGR] 2.2.3.1
/// requires; IronRDP rejects it as undecodable, FreeRDP accepts it. Recognises
/// exactly that: TPKT, X.224 data, MCS Send Data Indication, then a 6-byte
/// header of type PDUTYPE_DEACTIVATEALLPDU.
fn is_bare_deactivate_all(p: &[u8]) -> bool {
    const MCS_SEND_DATA_INDICATION: u8 = 26;
    if p.len() < 14 || p[..2] != [3, 0] || p[4..7] != [2, 0xf0, 0x80] || p[7] >> 2 != MCS_SEND_DATA_INDICATION {
        return false;
    }
    // PER length after initiator (2), channel (2) and flags (1).
    let (len, at) = if p[13] & 0x80 == 0 {
        (usize::from(p[13]), 14)
    } else {
        match p.get(14) {
            Some(lo) => (usize::from(p[13] & 0x3f) << 8 | usize::from(*lo), 15),
            None => return false,
        }
    };
    let data = &p[at..];
    len == 6 && data.len() == 6 && u16::from_le_bytes([data[0], data[1]]) == 6 && data[2] & 0x0f == 0x06
}

fn bulk_decompressor(ct: CompressionType) -> Option<ironrdp_bulk::BulkCompressor> {
    use ironrdp_bulk::CompressionType as Bulk;
    let bulk = match ct {
        CompressionType::K8 => Bulk::Rdp4,
        CompressionType::K64 => Bulk::Rdp5,
        CompressionType::Rdp6 => Bulk::Rdp6,
        CompressionType::Rdp61 => Bulk::Rdp61,
    };
    ironrdp_bulk::BulkCompressor::new(bulk).ok()
}

fn session_error(what: &str, e: impl std::fmt::Display) -> DesktopError {
    DesktopError::new("protocol", format!("The Remote Desktop session failed ({what}).")).with_details(e.to_string())
}

/// Runs the session until the server ends it or `rx` closes. `sink` gets the
/// messages for the webview; `behind` says how many bytes it hasn't drawn yet.
pub async fn run(
    c: Connected,
    sink: &(dyn Fn(Vec<u8>) + Send + Sync),
    rx: &mut mpsc::UnboundedReceiver<Cmd>,
    behind: &(dyn Fn() -> usize + Send + Sync),
) -> Result<(), DesktopError> {
    let Connected { framed, result } = c;
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let size = result.desktop_size;
    let compression = result.compression_type;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, size.width, size.height);
    let activation = result.activation_factory;
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();

    // The clipboard backend was created before its channel existed.
    let (clip_tx, mut clip_rx) = mpsc::unbounded_channel();
    if let Some(cl) = stage.get_svc_processor_mut::<CliprdrClient>()
        && let Some(b) = cl.downcast_backend_mut::<Clipboard>()
    {
        b.tx = Some(clip_tx.clone());
        for e in std::mem::take(&mut b.pending) {
            let _ = clip_tx.send(e);
        }
    }
    let mut local_text: Option<String> = None;

    let mut input = Database::new();
    let mut dirty = Dirty::default();
    dirty.add(full(&image));
    sink(size_message(&image));
    let mut flush_at: Option<tokio::time::Instant> = Some(tokio::time::Instant::now());
    let mut cleanup = tokio::time::interval(Duration::from_secs(5));

    loop {
        let outputs: Vec<ActiveStageOutput> = tokio::select! {
            frame = reader.read_pdu() => {
                let (action, payload) = frame.map_err(|e| DesktopError::new("ended", "The remote desktop session ended.").with_details(e.to_string()))?;
                if action == ironrdp_pdu::Action::X224 && is_bare_deactivate_all(&payload) {
                    vec![ActiveStageOutput::DeactivateAll]
                } else {
                    stage.process(&mut image, action, &payload).map_err(|e| session_error("decoding", e))?
                }
            }
            cmd = rx.recv() => match cmd {
                None => return Ok(()),
                Some(Cmd::Input(events)) => {
                    let mut fp = Vec::new();
                    for e in &events {
                        if matches!(e, Input::ReleaseAll) {
                            fp.extend(input.release_all());
                        }
                    }
                    fp.extend(input.apply(operations(events, (image.width(), image.height()))));
                    stage.process_fastpath_input(&mut image, &fp).map_err(|e| session_error("input", e))?
                }
                Some(Cmd::Resize(w, h)) => {
                    let (w, h) = MonitorLayoutEntry::adjust_display_size(u32::from(w), u32::from(h));
                    match stage.encode_resize(w, h, None, None) {
                        Some(frame) => vec![ActiveStageOutput::ResponseFrame(frame.map_err(|e| session_error("resize", e))?)],
                        None => Vec::new(), // the server can't resize; the view scales instead
                    }
                }
                Some(Cmd::Clipboard(text)) => {
                    local_text = Some(text);
                    let _ = clip_tx.send(ClipEvent::Announce);
                    Vec::new()
                }
            },
            Some(ev) = clip_rx.recv() => {
                let Some(cl) = stage.get_svc_processor_mut::<CliprdrClient>() else { continue };
                let msgs = match ev {
                    ClipEvent::Announce => {
                        let formats: Vec<ClipboardFormat> =
                            local_text.iter().map(|_| ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)).collect();
                        cl.initiate_copy(&formats)
                    }
                    ClipEvent::RemoteText => cl.initiate_paste(ClipboardFormatId::CF_UNICODETEXT),
                    ClipEvent::Requested(f) => cl.submit_format_data(match (&local_text, f == ClipboardFormatId::CF_UNICODETEXT) {
                        (Some(t), true) => OwnedFormatDataResponse::new_unicode_string(t),
                        _ => OwnedFormatDataResponse::new_error(),
                    }),
                    ClipEvent::Received(text) => {
                        if text.len() <= MAX_CLIPBOARD {
                            let mut m = vec![CLIPBOARD];
                            m.extend_from_slice(text.as_bytes());
                            sink(m);
                        }
                        continue;
                    }
                };
                match msgs {
                    Ok(m) => vec![ActiveStageOutput::ResponseFrame(stage.process_svc_processor_messages(m).map_err(|e| session_error("clipboard", e))?)],
                    Err(e) => {
                        tracing::debug!("clipboard: {e}");
                        Vec::new()
                    }
                }
            }
            () = async { tokio::time::sleep_until(flush_at.unwrap_or_else(tokio::time::Instant::now)).await }, if flush_at.is_some() => {
                // Coalesce updates for a few milliseconds, and hold them back
                // (merging) while the webview hasn't drawn what it has.
                if behind() > BEHIND {
                    flush_at = Some(tokio::time::Instant::now() + Duration::from_millis(16));
                } else {
                    for r in std::mem::take(&mut dirty.0) {
                        if let Some(m) = encode_rect(&image, &r) {
                            sink(m);
                        }
                    }
                    flush_at = None;
                }
                continue;
            }
            _ = cleanup.tick() => {
                let Some(cl) = stage.get_svc_processor_mut::<CliprdrClient>() else { continue };
                match cl.drive_timeouts() {
                    Ok(m) => {
                        let frame = stage.process_svc_processor_messages(m).map_err(|e| session_error("clipboard", e))?;
                        if frame.is_empty() { Vec::new() } else { vec![ActiveStageOutput::ResponseFrame(frame)] }
                    }
                    Err(_) => Vec::new(),
                }
            }
        };

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => {
                    if !frame.is_empty() {
                        writer
                            .write_all(&frame)
                            .await
                            .map_err(|e| DesktopError::new("ended", "The remote desktop session ended.").with_details(e.to_string()))?;
                    }
                }
                ActiveStageOutput::GraphicsUpdate(r) => {
                    dirty.add(r);
                    flush_at.get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_millis(8));
                }
                ActiveStageOutput::PointerDefault => sink(vec![CURSOR_DEFAULT]),
                ActiveStageOutput::PointerHidden => sink(vec![CURSOR_HIDDEN]),
                ActiveStageOutput::PointerBitmap(p) => {
                    let n = usize::from(p.width) * usize::from(p.height) * 4;
                    if p.width <= 256 && p.height <= 256 && p.bitmap_data.len() >= n {
                        let mut m = vec![CURSOR];
                        for v in [p.hotspot_x, p.hotspot_y, p.width, p.height] {
                            m.extend_from_slice(&v.to_le_bytes());
                        }
                        m.extend_from_slice(&p.bitmap_data[..n]);
                        sink(m);
                    }
                }
                ActiveStageOutput::PointerPosition { .. }
                | ActiveStageOutput::MultitransportRequest(_)
                | ActiveStageOutput::AutoDetect(_) => {}
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation (e.g. after a resize): a new desktop size.
                    let mut seq = activation.create();
                    let mut buf = WriteBuf::new();
                    loop {
                        let written = single_sequence_step_read(&mut reader, &mut seq, &mut buf)
                            .await
                            .map_err(|e| session_error("reactivation", e))?;
                        if written.size().is_some() {
                            writer.write_all(buf.filled()).await.map_err(|e| session_error("reactivation", e))?;
                        }
                        if let ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            enable_server_pointer,
                            pointer_software_rendering,
                        } = seq.connection_activation_state()
                        {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: seq.io_channel_id(),
                                    user_channel_id: seq.user_channel_id(),
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    // IronRDP's own client passes None here, but the
                                    // server keeps compressing after a reactivation.
                                    bulk_decompressor: compression.and_then(bulk_decompressor),
                                }
                                .build(),
                            );
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            sink(size_message(&image));
                            dirty = Dirty::default();
                            dirty.add(full(&image));
                            flush_at = Some(tokio::time::Instant::now());
                            break;
                        }
                    }
                }
                ActiveStageOutput::Terminate(reason) => {
                    return Err(DesktopError::new("ended", "The remote desktop session ended.").with_details(reason.description()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_and_flags() {
        assert_eq!(split_account("CORP\\alice"), (Some("CORP".into()), "alice".into()));
        assert_eq!(split_account("alice@corp.example"), (None, "alice@corp.example".into()));
        assert!(performance(Quality::Low).contains(PerformanceFlags::DISABLE_WALLPAPER));
        assert!(!performance(Quality::High).contains(PerformanceFlags::DISABLE_WALLPAPER));
    }

    #[test]
    fn rectangles_are_clipped_and_opaque() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 4, 3);
        let m = encode_rect(&image, &InclusiveRectangle { left: 2, top: 1, right: 10, bottom: 10 }).unwrap();
        assert_eq!(&m[..9], &[RECT, 2, 0, 1, 0, 2, 0, 2, 0]);
        assert_eq!(m.len(), 9 + 2 * 2 * 4);
        assert!(m[9..].chunks(4).all(|p| p[3] == 0xff));
        assert!(encode_rect(&image, &InclusiveRectangle { left: 9, top: 0, right: 10, bottom: 1 }).is_none());

        let mut d = Dirty::default();
        for i in 0..20u16 {
            d.add(InclusiveRectangle { left: i, top: i, right: i + 1, bottom: i + 1 });
        }
        assert!(d.0.len() <= MAX_RECTS);
        assert!(d.0.iter().any(|r| r.left == 0 && r.top == 0), "merged into a bounding box");
    }

    #[test]
    fn xrdp_bare_deactivate_all() {
        // Captured from xrdp 0.10 after a Display Control resize.
        let pdu = [3, 0, 0, 20, 2, 0xf0, 0x80, 0x68, 0, 5, 3, 0xeb, 0x70, 6, 6, 0, 0x16, 0, 0xee, 3];
        assert!(is_bare_deactivate_all(&pdu));
        let mut demand_active = pdu;
        demand_active[16] = 0x11; // PDUTYPE_DEMANDACTIVEPDU
        assert!(!is_bare_deactivate_all(&demand_active));
        assert!(!is_bare_deactivate_all(&pdu[..19]));
        assert!(!is_bare_deactivate_all(&[3, 0, 0, 4]));
    }

    #[test]
    fn input_is_bounded() {
        let ops = operations(
            vec![
                Input::Mouse { x: 5000, y: 5000 },
                Input::Unicode { ch: 0x0007, down: true },
                Input::Unicode { ch: 0xd800, down: true },
                Input::Wheel { delta: i16::MAX, horizontal: false },
                Input::Key { scancode: 0x1e, extended: false, down: true },
            ],
            (1280, 800),
        );
        assert_eq!(ops.len(), 3, "control and invalid characters are dropped");
        assert!(matches!(ops[0], Operation::MouseMove(MousePosition { x: 1279, y: 799 })));
        assert!(matches!(ops[1], Operation::WheelRotations(WheelRotations { rotation_units: 1200, .. })));
        let parsed: Vec<Input> = serde_json::from_str(r#"[{"type":"button","button":"left","down":true},{"type":"releaseAll"}]"#).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(serde_json::from_str::<Input>(r#"{"type":"key","scancode":300,"extended":false,"down":true}"#).is_err());
    }
}
