"""Minimal WebDriver client (stdlib only) for smoke-testing the app via tauri-driver."""
import base64, json, sys, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:4444"

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return json.loads(resp.read() or b"{}").get("value")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path}: {e.code} {e.read()[:800]!r}") from None

class Session:
    def __init__(self, app):
        v = req("POST", "/session", {"capabilities": {"alwaysMatch": {"tauri:options": {"application": app}}}})
        self.id = v["sessionId"]
    def find(self, css, timeout=15):
        end = time.time() + timeout
        while True:
            try:
                el = req("POST", f"/session/{self.id}/element", {"using": "css selector", "value": css})
                return next(iter(el.values()))  # W3C key or legacy "ELEMENT"
            except Exception as e:
                if time.time() > end:
                    raise RuntimeError(f"element not found: {css} ({e})") from None
                time.sleep(0.3)
    def click(self, css, timeout=15):
        req("POST", f"/session/{self.id}/element/{self.find(css, timeout)}/click", {})
    def type(self, css, text):
        req("POST", f"/session/{self.id}/element/{self.find(css)}/value", {"text": text})
    def clear(self, css):
        req("POST", f"/session/{self.id}/element/{self.find(css)}/clear", {})
    def text(self, css):
        return req("GET", f"/session/{self.id}/element/{self.find(css)}/text")
    def js(self, script, *args):
        return req("POST", f"/session/{self.id}/execute/sync", {"script": script, "args": list(args)})
    def shot(self, path):
        open(path, "wb").write(base64.b64decode(req("GET", f"/session/{self.id}/screenshot")))
    def wait_text(self, needle, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            body = self.js("return document.body.innerText")
            if needle in body:
                return body
            time.sleep(0.4)
        raise RuntimeError(f"text not found: {needle!r}\n---\n{body[:2000]}")
    def close(self):
        try:
            req("DELETE", f"/session/{self.id}")
        except Exception:
            pass
