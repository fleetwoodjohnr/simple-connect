import { readFileSync } from 'node:fs';
const pkg = JSON.parse(readFileSync('package.json'));
const config = JSON.parse(readFileSync('src-tauri/tauri.conf.json'));
const cargo = readFileSync('Cargo.toml', 'utf8').match(/^version = "([^"]+)"/m)?.[1];
const tag = process.env.RELEASE_TAG || `v${pkg.version}`;
if (!/^v\d+\.\d+\.\d+$/.test(tag) || [pkg.version, config.version, cargo].some(v => `v${v}` !== tag)) throw new Error('Tag/npm/Cargo/Tauri version mismatch');
if (config.plugins.updater.pubkey.includes('REPLACE') || config.plugins.updater.endpoints.some(url => !url.startsWith('https://github.com/fleetwoodjohnr/simple-connect/releases/'))) throw new Error('Release updater is not configured');
console.log(`Validated ${tag}`);
