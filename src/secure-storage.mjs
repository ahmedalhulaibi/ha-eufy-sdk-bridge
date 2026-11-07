// The host supplies encryption and manual unlock. This module requires the
// expected private ZFS mount before reading credentials or writing SDK state.
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { loadConfig } from "./config.mjs";
import { registerSecrets } from "./redact.mjs";

const C = fs.constants;
const LIMIT = 4 * 1024 * 1024;
const PRIVATE_FLAGS = C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK;
const SECRET_ENV = ["EUFY_EMAIL", "EUFY_PASSWORD", "SOLIX_EMAIL", "SOLIX_PASSWORD"];

export class StorageError extends Error {
  constructor(message = "Encrypted credential storage is unavailable or unsafe") {
    super(message);
    this.name = "StorageError";
  }
}

function privateFile(info, directory = false) {
  if (
    !(directory ? info.isDirectory() : info.isFile()) ||
    info.uid !== process.geteuid() ||
    (info.mode & 0o777) !== (directory ? 0o700 : 0o600) ||
    (!directory && info.nlink !== 1)
  )
    throw new StorageError();
}

function readPrivate(file, limit = LIMIT) {
  const fd = fs.openSync(file, PRIVATE_FLAGS);
  try {
    const info = fs.fstatSync(fd);
    privateFile(info);
    if (info.size > limit) throw new StorageError();
    const bytes = Buffer.alloc(limit + 1);
    const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (length > limit) throw new StorageError();
    return bytes.subarray(0, length).toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
}

function decodeMount(value) {
  return value.replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8)));
}

export class SecureStorage {
  constructor({
    root = "/data",
    guard = "/run/eufy-storage.json",
    mountInfo = () => fs.readFileSync("/proc/self/mountinfo", "utf8"),
  } = {}) {
    this.root = path.resolve(root);
    this.guard = guard;
    this.mountInfo = mountInfo;
    this.fd = undefined;
    try {
      this.policy = JSON.parse(readPrivate(guard, 4096));
      if (
        this.policy.version !== 1 ||
        this.policy.require_mount !== true ||
        !/^[0-9a-f]{32}$/.test(this.policy.volume_id ?? "") ||
        !/^[A-Za-z][A-Za-z0-9_.:-]*(\/[A-Za-z0-9_.:-]+)+$/.test(this.policy.dataset ?? "")
      )
        throw new StorageError();
      this.fd = fs.openSync(this.root, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
      this.check();
      this.ensureDirectory("state");
    } catch {
      this.close();
      throw new StorageError();
    }
  }

  get pinnedRoot() {
    if (this.fd === undefined) throw new StorageError();
    return `/proc/${process.pid}/fd/${this.fd}`;
  }

  check() {
    try {
      const info = fs.fstatSync(this.fd);
      privateFile(info, true);
      const current = fs.lstatSync(this.root);
      if (current.dev !== info.dev || current.ino !== info.ino || !current.isDirectory()) throw new StorageError();
      const mounts = this.mountInfo()
        .trim()
        .split("\n")
        .map((line) => {
          const [left, right] = line.split(" - ");
          return { point: decodeMount(left.split(" ")[4] ?? ""), fields: (right ?? "").split(" ") };
        });
      if (
        !mounts.some(
          (m) =>
            m.point === this.root && m.fields[0] === "zfs" && decodeMount(m.fields[1] ?? "") === this.policy.dataset,
        )
      )
        throw new StorageError();
      if (readPrivate(`${this.pinnedRoot}/.eufy-volume-id`, 64).trim() !== this.policy.volume_id)
        throw new StorageError();
    } catch {
      throw new StorageError();
    }
  }

  ensureDirectory(name) {
    this.check();
    if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new StorageError();
    const directory = `${this.pinnedRoot}/${name}`;
    try {
      try {
        fs.mkdirSync(directory, { mode: 0o700 });
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
      }
      const fd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
      try {
        privateFile(fs.fstatSync(fd), true);
      } finally {
        fs.closeSync(fd);
      }
      return directory;
    } catch {
      throw new StorageError();
    }
  }

  credentials() {
    this.check();
    try {
      const data = JSON.parse(readPrivate(`${this.pinnedRoot}/credentials.json`, 32768));
      if (data.version !== 1) throw new StorageError();
      for (const account of [data.eufy, ...(data.solix ? [data.solix] : [])]) {
        if (
          !account ||
          typeof account.email !== "string" ||
          !account.email.includes("@") ||
          account.email.length > 320 ||
          typeof account.password !== "string" ||
          !account.password ||
          account.password.length > 4096 ||
          !/^[A-Z]{2}$/.test(account.country ?? "")
        )
          throw new StorageError();
      }
      registerSecrets(data);
      return data;
    } catch {
      throw new StorageError("Encrypted credentials are missing or invalid; run the private configuration command");
    }
  }

  close() {
    if (this.fd !== undefined) fs.closeSync(this.fd);
    this.fd = undefined;
  }
}

export class SecureJsonStore {
  constructor(storage, name) {
    if (!/^[a-z][a-z0-9-]*\.json$/.test(name)) throw new StorageError();
    this.storage = storage;
    this.name = name;
  }

  withDirectory(operation) {
    this.storage.check();
    let fd;
    try {
      fd = fs.openSync(this.storage.ensureDirectory("state"), C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
      privateFile(fs.fstatSync(fd), true);
      return operation(`/proc/self/fd/${fd}`, fd);
    } catch {
      throw new StorageError("Cannot access private encrypted session storage");
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }

  load() {
    return this.withDirectory((directory) => {
      let text;
      try {
        text = readPrivate(`${directory}/${this.name}`);
      } catch (error) {
        if (error.code === "ENOENT") return null;
        throw error;
      }
      const data = JSON.parse(text);
      if (!data || typeof data !== "object" || Array.isArray(data)) throw new StorageError();
      registerSecrets(data);
      return data;
    });
  }

  save(data) {
    registerSecrets(data);
    return this.withDirectory((directory, directoryFd) => {
      const destination = `${directory}/${this.name}`;
      try {
        readPrivate(destination);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      const bytes = Buffer.from(JSON.stringify(data));
      if (bytes.length > LIMIT || !data || typeof data !== "object" || Array.isArray(data)) throw new StorageError();
      const temporary = `${directory}/.pending-${randomBytes(16).toString("hex")}`;
      let fd;
      try {
        fd = fs.openSync(temporary, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
        fs.writeFileSync(fd, bytes);
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        fd = undefined;
        fs.renameSync(temporary, destination);
        fs.fsyncSync(directoryFd);
      } finally {
        if (fd !== undefined) fs.closeSync(fd);
        try {
          fs.unlinkSync(temporary);
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
      }
    });
  }

  clear() {
    return this.withDirectory((directory, fd) => {
      try {
        readPrivate(`${directory}/${this.name}`);
      } catch (error) {
        if (error.code === "ENOENT") return;
        throw error;
      }
      fs.unlinkSync(`${directory}/${this.name}`);
      fs.fsyncSync(fd);
    });
  }
}

export function loadSecureConfig(env = process.env, options = {}) {
  if (SECRET_ENV.some((name) => env[name] !== undefined))
    throw new StorageError("Cloud credentials in environment variables are refused; use the encrypted credential file");
  if (/^(1|true|yes|on)$/i.test(env.BRIDGE_DEBUG_P2P ?? ""))
    throw new StorageError("Raw transport debug logging is disabled in this credential-storage fork");
  const storage = new SecureStorage(options);
  try {
    const credentials = storage.credentials();
    // This object stays inside Node. Never assign credentials to process.env,
    // Docker configuration, command arguments or a generated .env file.
    const state = storage.ensureDirectory("state");
    const config = loadConfig({
      ...env,
      EUFY_EMAIL: credentials.eufy.email,
      EUFY_PASSWORD: credentials.eufy.password,
      EUFY_COUNTRY: credentials.eufy.country,
      EUFY_SESSION: `${state}/eufy-session.json`,
      SOLIX_EMAIL: credentials.solix?.email,
      SOLIX_PASSWORD: credentials.solix?.password,
      SOLIX_COUNTRY: credentials.solix?.country,
      SOLIX_SESSION: `${state}/solix-session.json`,
      GO2RTC_CONFIG: `${state}/go2rtc.yaml`,
      BRIDGE_DEBUG_P2P: "0",
    });
    config.storage = storage;
    config.stores = {
      eufy: new SecureJsonStore(storage, "eufy-session.json"),
      push: new SecureJsonStore(storage, "eufy-fcm.json"),
      solix: new SecureJsonStore(storage, "solix-session.json"),
    };
    config.cfg.sessionStore = config.stores.eufy;
    config.cfg.pushSession = `${state}/eufy-fcm.json`;
    return config;
  } catch (error) {
    storage.close();
    throw error;
  }
}
