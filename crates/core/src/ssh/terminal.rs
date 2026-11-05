//! Interactive shell: `ssh -S <socket> -tt` inside a local PTY, so window-size
//! changes propagate to the remote terminal.
//!
//! Output is read on a dedicated thread in chunks of up to 64 KiB (natural
//! batching under load) with soft backpressure: once the frontend is more than
//! `HIGH_WATER` bytes behind it must acknowledge output before more is read,
//! which keeps memory bounded and the UI responsive during floods.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};

const HIGH_WATER: usize = 2 * 1024 * 1024;
const LOW_WATER: usize = 256 * 1024;

#[derive(Default)]
struct Flow {
    unacked: Mutex<usize>,
    cond: Condvar,
}

pub struct Terminal {
    writer: Mutex<Box<dyn Write + Send>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
    flow: Arc<Flow>,
}

fn size(cols: u16, rows: u16) -> PtySize {
    PtySize { rows: rows.clamp(2, 1000), cols: cols.clamp(2, 1000), pixel_width: 0, pixel_height: 0 }
}

impl Terminal {
    /// Spawns `ssh <args>` in a new PTY. `on_output` runs on the reader thread;
    /// `on_exit` runs once when the remote shell or connection ends.
    pub fn spawn(
        ssh: &Path,
        args: Vec<OsString>,
        env: Vec<(String, String)>,
        cols: u16,
        rows: u16,
        mut on_output: impl FnMut(Vec<u8>) + Send + 'static,
        on_exit: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<Terminal> {
        let pair = native_pty_system().openpty(size(cols, rows)).map_err(std::io::Error::other)?;
        let mut cmd = CommandBuilder::new(ssh);
        cmd.args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        let child = pair.slave.spawn_command(cmd).map_err(std::io::Error::other)?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(std::io::Error::other)?;
        let writer = pair.master.take_writer().map_err(std::io::Error::other)?;

        let flow: Arc<Flow> = Arc::default();
        let thread_flow = flow.clone();
        std::thread::Builder::new().name("terminal-reader".into()).spawn(move || {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        on_output(buf[..n].to_vec());
                        let Ok(mut unacked) = thread_flow.unacked.lock() else { break };
                        *unacked += n;
                        if *unacked > HIGH_WATER {
                            // Soft limit: a frontend that stops acknowledging slows output
                            // down instead of freezing it.
                            let _ = thread_flow.cond.wait_timeout_while(unacked, Duration::from_secs(2), |u| *u > LOW_WATER);
                        }
                    }
                }
            }
            on_exit();
        })?;

        Ok(Terminal { writer: Mutex::new(writer), master: Mutex::new(pair.master), child: Mutex::new(child), flow })
    }

    pub fn write(&self, data: &[u8]) -> std::io::Result<()> {
        let mut w = self.writer.lock().map_err(|_| std::io::Error::other("terminal writer poisoned"))?;
        w.write_all(data)?;
        w.flush()
    }

    pub fn resize(&self, cols: u16, rows: u16) -> std::io::Result<()> {
        let m = self.master.lock().map_err(|_| std::io::Error::other("terminal poisoned"))?;
        m.resize(size(cols, rows)).map_err(std::io::Error::other)
    }

    /// The frontend has rendered `bytes` of output.
    pub fn ack(&self, bytes: usize) {
        if let Ok(mut u) = self.flow.unacked.lock() {
            *u = u.saturating_sub(bytes);
            if *u <= LOW_WATER {
                self.flow.cond.notify_all();
            }
        }
    }

    pub fn kill(&self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Uses /bin/sh in place of ssh to exercise the PTY plumbing.
    #[test]
    fn echoes_through_pty_and_reports_exit() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let (exit_tx, exit_rx) = mpsc::channel::<()>();
        let term = Terminal::spawn(
            Path::new("/bin/sh"),
            vec!["-c".into(), "stty size; read x; echo got:$x".into()],
            vec![],
            100,
            30,
            move |b| {
                let _ = tx.send(b);
            },
            move || {
                let _ = exit_tx.send(());
            },
        )
        .unwrap();
        term.write(b"hello\n").unwrap();
        exit_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let out: Vec<u8> = rx.try_iter().flatten().collect();
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("30 100"), "pty size propagated: {out:?}");
        assert!(out.contains("got:hello"), "{out:?}");
    }
}
