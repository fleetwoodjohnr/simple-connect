"""Smoke test: quick connect → trust host → password → terminal → files → info → settings."""
import os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wd import Session, req  # noqa: E402

APP, PORT, OUT = os.environ["APP"], os.environ["SSHD_PORT"], os.environ["OUT"]
# podman must see the real user's image store, not the app's isolated home.
PODMAN_ENV = {k: v for k, v in os.environ.items() if not k.startswith("XDG_") or k == "XDG_RUNTIME_DIR"} | {"HOME": os.environ["REAL_HOME"]}
ENTER = ""


def click_text(s, text, tag="button"):
    ok = s.js(
        "const b=[...document.querySelectorAll(arguments[1])].find(e=>e.textContent.trim().includes(arguments[0])&&!e.disabled); if(b){b.click(); return true} return false",
        text,
        tag,
    )
    if not ok:
        raise RuntimeError(f"no enabled {tag} with text {text!r}")


s = Session(APP)
try:
    req("POST", f"/session/{s.id}/window/rect", {"width": 1280, "height": 800})
    s.wait_text("Connect to a server", 40)
    s.shot(f"{OUT}/01-home.png")

    s.type("input[aria-label=Destination]", f"pw@127.0.0.1 -p {PORT}")
    s.wait_text(f"pw@127.0.0.1:{PORT}")
    s.type("input[aria-label=Destination]", ENTER)

    s.wait_text("Check this server's identity")
    time.sleep(0.4)
    s.shot(f"{OUT}/02-host-key.png")
    click_text(s, "Trust and connect")

    s.wait_text("Enter your password")
    s.type("input[type=password]", "correct horse")
    time.sleep(0.2)
    s.shot(f"{OUT}/03-password.png")
    click_text(s, "Continue")

    s.wait_text("Connected securely", 30)
    time.sleep(1.5)
    s.type(".xterm-helper-textarea", "echo hello-from-$(whoami) && uname -s" + ENTER)
    s.wait_text("Shell")
    time.sleep(1.5)
    s.shot(f"{OUT}/04-terminal.png")

    # sudo asks for the password: the hint offers the login password; Enter sends it.
    s.type(".xterm-helper-textarea", "sudo -k; sudo sh -c 'id -u > /tmp/sudo-ok'" + ENTER)
    s.wait_text("to use your SSH password", 20)
    time.sleep(0.3)
    s.shot(f"{OUT}/04b-sudo-offer.png")
    s.type(".xterm-helper-textarea", ENTER)
    for _ in range(40):
        out = subprocess.run(["podman", "exec", "sc-e2e", "cat", "/tmp/sudo-ok"], capture_output=True, env=PODMAN_ENV)
        if out.stdout.strip() == b"0":
            break
        time.sleep(0.25)
    assert out.stdout.strip() == b"0", "sudo ran as root with the reused password"
    assert "to use your SSH password" not in s.js("return document.body.innerText"), "hint gone after sending"

    # Name the quick connection so it shows up as "Test Box" from now on.
    click_text(s, "Connection")
    click_text(s, "Save as connection")
    s.wait_text("New connection")
    s.clear("#" + s.js("return [...document.querySelectorAll('label')].find(l=>l.textContent==='Name').htmlFor"))
    s.type("[role=dialog] input", "Test Box")
    click_text(s, "Save connection")
    s.wait_text("Test Box")
    assert "Test Box" in s.js("return document.querySelector('[role=tab][aria-selected=true]').textContent"), "tab shows the friendly name"
    click_text(s, "Terminal")

    click_text(s, "Files")
    s.wait_text("This computer")
    time.sleep(1.5)
    s.shot(f"{OUT}/05-files.png")

    click_text(s, "Connection")
    s.wait_text("Connection security")
    click_text(s, "Connection security")
    time.sleep(0.5)
    s.shot(f"{OUT}/06-info.png")
    body = s.js("return document.body.innerText")
    assert "Host fingerprint" in body and "SHA256:" in body, body[:500]

    s.click("button[aria-label=Settings]")
    s.wait_text("Appearance")
    s.shot(f"{OUT}/07-settings.png")
    click_text(s, "Security")
    s.wait_text("Trusted servers")
    time.sleep(0.5)
    s.shot(f"{OUT}/08-security.png")
    assert "[127.0.0.1]:" + PORT in s.js("return document.body.innerText"), "trusted host listed"
    click_text(s, "Back")

    # A refused connection explains itself instead of showing raw errors.
    s.click("button[aria-label=Home]")
    s.type("input[aria-label=Destination]", "pw@127.0.0.1 -p 9")
    s.wait_text("pw@127.0.0.1:9")
    s.type("input[aria-label=Destination]", ENTER)
    s.wait_text("refused the connection", 30)
    s.shot(f"{OUT}/09-refused.png")

    # The server is rebuilt with new host keys: the change is blocked.
    subprocess.run(["podman", "rm", "-f", "-t", "0", "sc-e2e"], capture_output=True, env=PODMAN_ENV)
    for _ in range(20):  # the name and port are released asynchronously
        run = subprocess.run(["podman", "run", "-d", "--rm", "--name", "sc-e2e", "-p", f"127.0.0.1:{PORT}:22", "simple-connect-sshd"], capture_output=True, env=PODMAN_ENV)
        if run.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(run.stderr.decode())
    # The first session reconnects on its own and meets the new key.
    s.wait_text("The SSH identity of this server has changed", 60)
    time.sleep(0.4)
    s.shot(f"{OUT}/10-changed-key.png")
    assert not s.js("return [...document.querySelectorAll('button')].find(b=>b.textContent.includes('Trust new key')).disabled===false"), "trust needs the typed host name"
    click_text(s, "Disconnect")
    click_text(s, "Test Box", "[role=tab]")
    s.wait_text("identity has changed since you last connected", 30)
    s.shot(f"{OUT}/11-changed-key-blocked.png")
    # The network scanner opens on a local network without scanning anything.
    s.click("button[aria-label=Home]")
    click_text(s, "Find devices on your network")
    s.wait_text("Devices on your network")
    time.sleep(0.5)
    assert s.js("return document.querySelectorAll('[role=dialog] select option').length") >= 1
    s.shot(f"{OUT}/12-scanner.png")
    print("E2E OK")
finally:
    s.close()
