# Eufy bridge with encrypted cloud-credential storage

This fork of [mega-yfue/ha-eufy-sdk-bridge](https://github.com/mega-yfue/ha-eufy-sdk-bridge)
protects Eufy cloud passwords, session tokens, negotiated keys and push credentials
using an operator-provisioned encrypted filesystem. Version **0.7.3** uses the
stable upstream 0.7.2 runtime/SDK image pinned to an immutable digest.

## Storage protection

- Cloud credentials load from owner-only `/data/credentials.json` into memory.
  They are never assigned to `process.env`, Docker environment, command arguments,
  Compose configuration or an unencrypted `.env` file.
- Startup requires a private ZFS mount, the expected dataset name, an outside
  storage guard and matching volume marker. Missing/locked storage has no
  plaintext fallback. The guard alone does not create encryption: host
  provisioning must verify native ZFS AES-256-GCM and manual key loading.
- Eufy sessions, stream-client sessions, push registrations and optional Solix
  sessions use the same guarded store. Writes replace files atomically and fsync
  the file and containing directory. Corrupt JSON, unsafe permissions, symlinks
  and hardlinks fail closed.
- Session files and credentials are 0600; directories are 0700. All data and
  retained private imagery stay on the encrypted volume. The container runs as
  UID 10001 with a read-only root filesystem, no capabilities, no new privileges,
  core dumps disabled and temporary storage in RAM.
- Logs and protocol errors redact known secret values and sensitive fields.
  Raw P2P debug logging is refused. Never share unreviewed diagnostics or dumps.

Encryption protects stored data when locked. The running bridge, its process UID,
root and administrators able to control Docker remain trusted while unlocked.
This is a focused storage-hardening fork, not a claim that every dependency or
Eufy protocol has received a complete security audit.

The Home Assistant integration can remain
[mega-yfue/ha-eufy-sdk](https://github.com/mega-yfue/ha-eufy-sdk).
LAN camera/control interfaces retain the upstream protocol; this fork does not
add client authentication to those interfaces.

## Media-server setup

See [deployment and recovery](docs/docker-compose.md). The prepared host uses a
separate `media-pool/qolsys-credentials/eufy` dataset mounted at
`/media-server/secure-eufy`, inheriting the existing manually unlocked credential
key. The bridge receives only this child dataset, without Qolsys/MyQ secrets.

Enter account details only in your own interactive terminal:

```bash
ssh -t ahmed@100.106.82.72 'sudo /usr/local/sbin/eufy-storage configure'
ssh -t ahmed@100.106.82.72 'sudo /usr/local/sbin/eufy-storage start'
```

`configure` hides both email and password, writes directly to the encrypted
volume and attempts no login. `start` first validates storage offline with
networking disabled, then starts the bridge. Finish any 2FA/captcha through the
Home Assistant integration. Use bridge address **192.168.50.69:3012** and RTSP
port **8556**. Account country must match the Eufy account's registration country.

After reboot, the existing unlock command loads the shared key, mounts Eufy and
resumes it if credentials are configured, then restarts Home Assistant:

```bash
ssh -t ahmed@100.106.82.72 'sudo /usr/local/sbin/qolsys-storage unlock'
```

An Eufy resume failure does not prevent Home Assistant from restarting.

## Validation and maintenance

```bash
npm ci --ignore-scripts
npm run lint
npm test
python3 -m unittest discover -s deploy -p 'test_*.py'
docker build -t eufy-bridge-secure:0.7.3 .
```

Tests use synthetic credentials and mocked devices. Do not operate real cameras,
alarms or locks in tests. Keep updates on this fork: the upstream image uses its
original credential-storage behavior. The release workflow targets this fork's
registry; no upstream PR or beta image is required.

[WS protocol](docs/ws-protocol.md) documents unchanged device/control capabilities.
