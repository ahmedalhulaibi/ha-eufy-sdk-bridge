import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SecureStorage, SecureJsonStore, StorageError, loadSecureConfig } from "../src/secure-storage.mjs";
import { registerSecrets, redactSecrets, redactPayload, installConsoleRedaction } from "../src/redact.mjs";
import { createEufy } from "../src/client.mjs";
import { streamClientOptions } from "../streams.mjs";
import { createSolix } from "../src/solix.mjs";

const VOLUME = "ab".repeat(16);
const DATASET = "test-pool/credentials/eufy";
const ACCOUNT = { email: "fixture@example.com", password: "fixture-password-secret", country: "CA" };

function fixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "eufy-storage-test-"));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const root = path.join(base, "volume");
  fs.mkdirSync(root, { mode: 0o700 });
  const guard = path.join(base, "guard.json");
  const put = (file, value) => fs.writeFileSync(file, value, { mode: 0o600 });
  put(guard, JSON.stringify({ version: 1, require_mount: true, volume_id: VOLUME, dataset: DATASET }));
  const marker = path.join(root, ".eufy-volume-id");
  put(marker, VOLUME);
  const credentials = path.join(root, "credentials.json");
  put(credentials, JSON.stringify({ version: 1, eufy: ACCOUNT }));
  const state = { mounted: true, dataset: DATASET, filesystem: "zfs" };
  const options = {
    root,
    guard,
    mountInfo: () => (state.mounted ? `100 90 0:12 / ${root} rw - ${state.filesystem} ${state.dataset} rw\n` : ""),
  };
  const open = () => {
    const storage = new SecureStorage(options);
    t.after(() => storage.close());
    return storage;
  };
  return { base, root, guard, marker, credentials, state, options, open, put };
}

test("secure config loads credentials only from private marked mounted storage", (t) => {
  const f = fixture(t);
  const config = loadSecureConfig({ EUFY_SESSION: "/outside/plaintext", GO2RTC_CONFIG: "/outside/config" }, f.options);
  t.after(() => config.storage.close());
  assert.equal(config.cfg.password, ACCOUNT.password);
  assert.equal(config.cfg.country, "CA");
  assert.match(config.cfg.session, /^\/proc\/\d+\/fd\/\d+\/state\/eufy-session.json$/);
  assert.match(config.cfg.go2rtcConfig, /^\/proc\/\d+\/fd\/\d+\/state\/go2rtc.yaml$/);
  assert.ok(config.stores.eufy instanceof SecureJsonStore);
  assert.ok(config.stores.push instanceof SecureJsonStore);
  assert.equal(streamClientOptions(config.cfg).store, config.stores.eufy);
  assert.equal(process.env.EUFY_PASSWORD, undefined);
  assert.equal(config.DEBUG_P2P, false);
});

for (const damage of [
  "missing-guard",
  "guard-mode",
  "guard-symlink",
  "guard-hardlink",
  "root-mode",
  "root-symlink",
  "marker-mode",
  "wrong-marker",
  "not-mounted",
  "wrong-dataset",
  "wrong-filesystem",
  "bad-guard",
]) {
  test(`storage refuses ${damage} before creating a state directory`, (t) => {
    const f = fixture(t);
    if (damage === "missing-guard") fs.unlinkSync(f.guard);
    if (damage === "guard-mode") fs.chmodSync(f.guard, 0o644);
    if (damage === "guard-symlink") {
      fs.renameSync(f.guard, `${f.guard}.real`);
      fs.symlinkSync(`${f.guard}.real`, f.guard);
    }
    if (damage === "guard-hardlink") fs.linkSync(f.guard, `${f.guard}.link`);
    if (damage === "root-mode") fs.chmodSync(f.root, 0o755);
    if (damage === "root-symlink") {
      fs.renameSync(f.root, `${f.root}-real`);
      fs.symlinkSync(`${f.root}-real`, f.root);
    }
    if (damage === "marker-mode") fs.chmodSync(f.marker, 0o644);
    if (damage === "wrong-marker") fs.writeFileSync(f.marker, "cd".repeat(16));
    if (damage === "not-mounted") f.state.mounted = false;
    if (damage === "wrong-dataset") f.state.dataset = "test-pool/plaintext";
    if (damage === "wrong-filesystem") f.state.filesystem = "ext4";
    if (damage === "bad-guard") fs.writeFileSync(f.guard, JSON.stringify({ version: 1, require_mount: false }));
    assert.throws(f.open, StorageError);
    assert.equal(fs.existsSync(path.join(f.root, "state")), false);
  });
}

for (const damage of ["mode", "symlink", "hardlink", "fifo", "invalid-json", "invalid-account"]) {
  test(`credentials refuse ${damage} without exposing contents`, (t) => {
    const f = fixture(t);
    if (damage === "mode") fs.chmodSync(f.credentials, 0o644);
    if (damage === "symlink") {
      fs.renameSync(f.credentials, `${f.credentials}.real`);
      fs.symlinkSync(`${f.credentials}.real`, f.credentials);
    }
    if (damage === "hardlink") fs.linkSync(f.credentials, `${f.credentials}.link`);
    if (damage === "fifo") {
      fs.unlinkSync(f.credentials);
      const { spawnSync } = process.getBuiltinModule("node:child_process");
      assert.equal(spawnSync("mkfifo", ["-m", "600", f.credentials]).status, 0);
    }
    if (damage === "invalid-json") fs.writeFileSync(f.credentials, "malformed-credential-" + ACCOUNT.password);
    if (damage === "invalid-account")
      fs.writeFileSync(f.credentials, JSON.stringify({ version: 1, eufy: { ...ACCOUNT, country: "Canada" } }));
    assert.throws(
      () => f.open().credentials(),
      (error) => error instanceof StorageError && !String(error).includes(ACCOUNT.password),
    );
  });
}

test("session records use atomic replacement and owner-only file modes", (t) => {
  const f = fixture(t);
  const storage = f.open();
  const store = new SecureJsonStore(storage, "eufy-session.json");
  assert.equal(store.load(), null);
  const record = { authToken: "session-token-fixture", shareKey: "session-key-fixture", keyIdent: "test-ident" };
  store.save(record);
  assert.deepEqual(store.load(), record);
  const file = path.join(f.root, "state/eufy-session.json");
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  store.save({ ...record, authToken: "rotated-token-fixture" });
  assert.equal(store.load().authToken, "rotated-token-fixture");
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ["eufy-session.json"]);
  store.clear();
  assert.equal(store.load(), null);
});

test("a failed atomic write retains previous tokens and removes temporary files", (t) => {
  const f = fixture(t),
    store = new SecureJsonStore(f.open(), "eufy-session.json");
  store.save({ authToken: "previous-token-fixture" });
  const original = fs.renameSync;
  fs.renameSync = () => {
    throw new Error("synthetic disk failure");
  };
  try {
    assert.throws(() => store.save({ authToken: "new-token-fixture" }), StorageError);
  } finally {
    fs.renameSync = original;
  }
  assert.equal(store.load().authToken, "previous-token-fixture");
  assert.deepEqual(fs.readdirSync(path.join(f.root, "state")), ["eufy-session.json"]);
});

for (const damage of ["symlink", "hardlink", "mode", "corrupt", "oversized"]) {
  test(`session load fails closed for ${damage}`, (t) => {
    const f = fixture(t),
      store = new SecureJsonStore(f.open(), "eufy-session.json");
    store.save({ authToken: "protected-token-fixture" });
    const file = path.join(f.root, "state/eufy-session.json");
    if (damage === "symlink") {
      fs.renameSync(file, `${file}.real`);
      fs.symlinkSync(`${file}.real`, file);
    }
    if (damage === "hardlink") fs.linkSync(file, `${file}.link`);
    if (damage === "mode") fs.chmodSync(file, 0o644);
    if (damage === "corrupt") fs.writeFileSync(file, "invalid-json-protected-token-fixture");
    if (damage === "oversized") fs.writeFileSync(file, "x".repeat(4 * 1024 * 1024 + 1));
    assert.throws(() => store.load(), StorageError);
    if (damage !== "corrupt") assert.throws(() => store.save({ authToken: "replacement-token" }), StorageError);
  });
}

test("mount and directory checks are repeated on every load, save and clear", (t) => {
  const f = fixture(t),
    store = new SecureJsonStore(f.open(), "eufy-session.json");
  store.save({ authToken: "fixture-token" });
  f.state.mounted = false;
  for (const operation of [() => store.load(), () => store.save({ authToken: "next" }), () => store.clear()])
    assert.throws(operation, StorageError);
  f.state.mounted = true;
  fs.renameSync(path.join(f.root, "state"), path.join(f.root, "original-state"));
  const outside = path.join(f.base, "outside");
  fs.mkdirSync(outside, { mode: 0o700 });
  fs.symlinkSync(outside, path.join(f.root, "state"));
  assert.throws(() => store.save({ authToken: "escape-attempt" }), StorageError);
  assert.deepEqual(fs.readdirSync(outside), []);
});

test("replacing mountpoint path cannot redirect writes to plaintext", (t) => {
  const f = fixture(t),
    store = new SecureJsonStore(f.open(), "eufy-session.json");
  fs.renameSync(f.root, `${f.root}-old`);
  fs.mkdirSync(f.root, { mode: 0o700 });
  assert.throws(() => store.save({ authToken: "escape-attempt" }), StorageError);
  assert.deepEqual(fs.readdirSync(f.root), []);
});

test("record names cannot escape the guarded state directory", (t) => {
  const storage = fixture(t).open();
  for (const name of ["../credentials.json", "/tmp/tokens.json", "", "a/../b.json"])
    assert.throws(() => new SecureJsonStore(storage, name), StorageError);
});

test("environment cloud secrets and raw transport debugging are refused", (t) => {
  const f = fixture(t);
  for (const name of ["EUFY_EMAIL", "EUFY_PASSWORD", "SOLIX_EMAIL", "SOLIX_PASSWORD"])
    assert.throws(() => loadSecureConfig({ [name]: "fixture-credential" }, f.options), StorageError);
  assert.throws(() => loadSecureConfig({ BRIDGE_DEBUG_P2P: "true" }, f.options), StorageError);
});

test("SDK clients have no unencrypted file-store fallback", () => {
  assert.throws(() => createEufy({ cfg: {}, DEBUG_P2P: false }), StorageError);
  assert.throws(() => streamClientOptions({}), StorageError);
  assert.throws(() => createSolix({ cfg: { solix: ACCOUNT } }), StorageError);
});

test("optional Solix credentials and sessions use the same encrypted boundary", (t) => {
  const f = fixture(t);
  f.put(
    f.credentials,
    JSON.stringify({ version: 1, eufy: ACCOUNT, solix: { ...ACCOUNT, email: "solix@example.com" } }),
  );
  const config = loadSecureConfig({}, f.options);
  t.after(() => config.storage.close());
  assert.equal(config.cfg.solix.email, "solix@example.com");
  config.stores.solix.save({ authToken: "solix-fixture-token" });
  assert.equal(config.stores.solix.load().authToken, "solix-fixture-token");
});

test("cloud credential values are removed from string, object and Error logs", () => {
  const secret = "unusual-secret-<cloud>";
  registerSecrets({ password: secret, nested: { securityToken: "push-fixture-security" } });
  for (const value of [
    secret,
    encodeURIComponent(secret),
    JSON.stringify({ authToken: secret }),
    "token = push-fixture-security",
  ])
    assert.ok(!redactSecrets(value).includes(secret));
  const lines = [],
    target = Object.fromEntries(
      ["log", "info", "warn", "error", "debug"].map((name) => [name, (...args) => lines.push(args)]),
    );
  installConsoleRedaction(target);
  target.log({ nested: { password: secret, shareKey: "unknown-key-secret" } });
  target.error(new Error(`cloud failed with ${secret}`));
  target.log(`arbitrary error echo ${secret}`);
  const output = JSON.stringify(lines.map((line) => line.map((item) => (item instanceof Error ? item.stack : item))));
  assert.ok(!output.includes(secret));
  assert.ok(!output.includes("unknown-key-secret"));
});

test("short session identifiers cannot corrupt JSON protocol numbers", () => {
  registerSecrets({ keyIdent: "1" });
  const serialized = JSON.stringify(redactPayload({ id: 123, value: 1, authToken: "unknown-token" }));
  assert.deepEqual(JSON.parse(serialized), { id: 123, value: 1, authToken: "<redacted>" });
});
