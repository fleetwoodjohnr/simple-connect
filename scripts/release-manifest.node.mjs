import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, randomBytes, createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { verifyArtifact, manifest } from './release-manifest.mjs';
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const id = randomBytes(8);
const packet = Buffer.concat([Buffer.from('Ed'), id, publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)]);
const pub = Buffer.from(`untrusted comment: test\n${packet.toString('base64')}\n`).toString('base64');
function signature(bytes) {
  const packet = Buffer.concat([Buffer.from('ED'), id, sign(null, createHash('blake2b512').update(bytes).digest(), privateKey)]);
  const global = sign(null, Buffer.concat([packet.subarray(10), Buffer.from('test\tversion:0.1.0')]), privateKey);
  return Buffer.from(`untrusted comment: test\n${packet.toString('base64')}\ntrusted comment: test\tversion:0.1.0\n${global.toString('base64')}\n`).toString('base64');
}
test('signatures verify bytes, reject tampering and invalid keys', () => {
  const bytes = Buffer.from('signed update');
  verifyArtifact(bytes, signature(bytes), pub, "0.1.0");
  assert.throws(() => verifyArtifact(bytes, signature(bytes), pub, "0.1.1"), /version/);
  assert.throws(() => verifyArtifact(Buffer.from('changed'), signature(bytes), pub));
  assert.throws(() => verifyArtifact(bytes, signature(bytes), 'not a key'));
  const changedComment = Buffer.from(Buffer.from(signature(bytes), 'base64').toString().replace('\ntrusted comment: test\t', '\ntrusted comment: tampered\t')).toString('base64');
  assert.throws(() => verifyArtifact(bytes, changedComment, pub));
});
test('manifest requires every architecture and bundle, with versioned URLs', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sc-release-'));
  try {
    await assert.rejects(manifest(root, 'v0.1.0', 'owner/repo', pub), /Incomplete/);
    for (const arch of ['x86_64', 'aarch64']) {
      for (const [osName, types] of [['linux', ['deb', 'rpm', 'AppImage']], ['windows', ['-setup.exe']], ['darwin', ['app.tar.gz']]]) {
        const dir = path.join(root, `${osName}-${arch}`);
        await mkdir(dir, { recursive: true });
        for (const ext of types) {
          const file = path.join(dir, `Simple Connect-${osName}-${arch}${ext === '-setup.exe' ? '' : '.'}${ext}`);
          const bytes = Buffer.from(file);
          await writeFile(file, bytes);
          await writeFile(`${file}.sig`, signature(bytes));
        }
      }
    }
    await assert.rejects(manifest(root, 'v0.1.0', 'owner/repo', pub), /Missing macOS DMG/);
    for (const arch of ['x86_64', 'aarch64']) await writeFile(path.join(root, `darwin-${arch}`, `app-${arch}.dmg`), 'disk image');
    await manifest(root, 'v0.1.0', 'owner/repo', pub);
    const m = JSON.parse(await readFile(path.join(root, 'latest.json')));
    assert.equal(Object.keys(m.platforms).length, 10);
    assert.match(await readFile(path.join(root, 'SHA256SUMS'), 'utf8'), /app-aarch64\.dmg/);
    assert.match(m.platforms['windows-aarch64-nsis'].url, /releases\/download\/v0.1.0\//);
    for (const entry of Object.values(m.platforms)) {
      assert.match(entry.url, /Simple\.Connect/);
      assert.doesNotMatch(entry.url, /%20/);
    }
    assert.equal(await readFile(path.join(root, 'windows-aarch64', 'windows-aarch64-Simple.Connect-windows-aarch64-setup.exe'), 'utf8'), path.join(root, 'windows-aarch64', 'Simple Connect-windows-aarch64-setup.exe'));
    await assert.rejects(manifest(root, 'untrusted tag', 'owner/repo', pub));
  } finally { await rm(root, { recursive: true, force: true }); }
});
