// Keep credentials out of what the bridge emits. eufy's servers echo the account's auth token back in some
// error messages ("token not exist, token = <token>"), the SDK passes that text through, and the bridge
// would otherwise print it in its log and return it in HTTP / WebSocket error bodies, which users paste
// into public issues. Redaction happens where text leaves the bridge, so no call site can forget it.

// `token = <value>` / `token=<value>` as eufy writes it. A JSON key (`"token":`) is not matched, so device
// data that carries such a field is left alone.
const TOKEN_ASSIGNMENT = /(\btoken\s*=\s*)[^\s,;)"'\\]+/gi;
const SECRET_KEY = /password|token|secret|private.?key|share.?key|key.?ident|auth.?key/i;
const JSON_SECRET =
  /("(?:password|[a-z_]*token|[a-z_]*secret|private_?key|share_?key|key_?ident|auth_?key)"\s*:\s*)"(?:\\.|[^"\\])*"/gi;
const knownSecrets = new Set();

// Register exact secret values as soon as credentials or session records enter
// the process, including JSON-escaped and URL-encoded renderings.
export function registerSecrets(value) {
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    if (SECRET_KEY.test(key) && typeof item === "string" && item) {
      for (const secret of [item, JSON.stringify(item).slice(1, -1), encodeURIComponent(item)]) {
        knownSecrets.add(secret);
        if (knownSecrets.size > 4096) knownSecrets.delete(knownSecrets.values().next().value);
      }
    } else if (item && typeof item === "object") registerSecrets(item);
  }
}

/** `text` with any echoed token value replaced by `<redacted>`. */
export function redactSecrets(text) {
  if (typeof text !== "string") return text;
  text = text.replace(TOKEN_ASSIGNMENT, "$1<redacted>").replace(JSON_SECRET, '$1"<redacted>"');
  for (const secret of [...knownSecrets].sort((a, b) => b.length - a.length))
    text = text.replaceAll(secret, "<redacted>");
  return text;
}

export function redactPayload(value, seen = new WeakSet(), depth = 0) {
  if (typeof value === "string") return redactSecrets(value);
  if (value instanceof Error) return redactError(value);
  if (!value || typeof value !== "object") return value;
  if (depth > 8 || seen.has(value)) return "<omitted>";
  if (Buffer.isBuffer(value)) return "<binary omitted>";
  seen.add(value);
  if (Array.isArray(value)) return value.map((v) => redactPayload(v, seen, depth + 1));
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      SECRET_KEY.test(key) ? "<redacted>" : redactPayload(item, seen, depth + 1),
    ]),
  );
}

/** Route console output through {@link redactSecrets}, covering the bridge's and the SDK's own logging. */
export function installConsoleRedaction(target = console) {
  for (const method of ["log", "info", "warn", "error", "debug"]) {
    const original = target[method].bind(target);
    target[method] = (...args) => original(...args.map((a) => redactPayload(a)));
  }
}

function redactError(e) {
  const copy = new Error(redactSecrets(e.message));
  copy.name = e.name;
  copy.stack = redactSecrets(e.stack);
  return copy;
}
