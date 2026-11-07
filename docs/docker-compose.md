# Encrypted deployment and recovery

This fork requires a Linux host with native ZFS encryption and a passphrase
entered manually after reboot. Its prepared deployment is specific to the media
server. A different host must provision equivalent storage and update the guard,
paths and UID deliberately before use.

## Host storage

- Dataset: `media-pool/qolsys-credentials/eufy`
- Mountpoint: `/media-server/secure-eufy`
- Encryption root: `media-pool/qolsys-credentials`, AES-256-GCM,
  passphrase, `keylocation=prompt`
- Child quota: 256 MiB, leaving room for Qolsys/MyQ in the parent credential quota
- Runtime owner: UID/GID 10001, directories 0700, private files 0600
- Outside runtime guard: `/etc/eufy-bridge/runtime-guard.json` (read-only bind)
- Root-only host settings: `/etc/eufy-bridge/storage.json`
- Compose configuration: `/etc/eufy-bridge/compose.yaml`

The child has its own mount and backup. It shares the parent's encryption key;
no second passphrase or plaintext key file is stored. Merely unmounting Eufy
while the parent's key remains loaded does not erase that key from RAM.

The runtime guard contains only version, required-mount flag, expected dataset
and a random volume ID. `/data/.eufy-volume-id` must match. The application checks
Linux mountinfo and the mounted directory's identity before using its pinned
filesystem descriptor. An ordinary directory at the same path cannot substitute
for the encrypted mount. Compose refuses to create missing bind-source paths.

`deploy/prepare-media-host.py --commit FULL_SHA` is a root-only fresh-deployment
script. It verifies a clean fork checkout and the existing encryption root,
builds the pinned runtime, creates only the new child dataset, installs the
private configuration helper and writes nonsecret Compose/guard metadata. It
refuses to overwrite an existing deployment or dataset. It does not configure
an account, sign in, start a bridge or operate devices.

`deploy/install-unlock-hook.py --expected-sha256 EXPECTED_HASH` patches only a
known existing unlock helper and saves its previous source root-only. It keeps
the native hidden passphrase prompt and makes Eufy resume independent of HA's
restart. Inspect the source/hash before applying this on any other machine.

## Credential entry

Run in a private interactive SSH terminal:

```bash
sudo /usr/local/sbin/eufy-storage configure
sudo /usr/local/sbin/eufy-storage start
```

Do not send credentials through chat, shell arguments, environment, `.env` or
Compose. The local helper hides both email and password. Country is a two-letter
code such as CA, matching the country used when the account was registered.

The encrypted credential file has version 1 with an `eufy` account containing
email, password and country. An optional `solix` account uses the same shape and
encrypted boundary; the interactive helper configures Eufy only. A root
administrator can add Solix privately without copying the file outside the
volume. Environment-based credentials are refused, including empty variables.

`start` checks storage inside the actual container image with networking disabled
before launching. Runtime environment contains only nonsecret tuning and paths.
The account password stays inside the Node process; go2rtc/ffmpeg children do not
inherit it through the environment. Session stores register token/key values for
redaction when loaded or saved. Raw transport debug is disabled in this fork.

## Home Assistant

Install the unchanged `mega-yfue/ha-eufy-sdk` integration and add a bridge at
`192.168.50.69`, control port 3012, RTSP port 8556. Complete any required 2FA or
captcha there. Eufy remains an unofficial cloud-dependent integration. The
maintainer warns that phone/bridge logins can displace sessions; validate this
with the chosen account. Hardware support depends on the actual device models.

Host networking preserves upstream LAN media/control behavior. Go2rtc uses API
1985, RTSP 8556 and WebRTC 8557 to avoid common default-port collisions. There
is no new LAN client-authentication layer in this storage-focused fork.

## Reboot and operation

```bash
sudo /usr/local/sbin/qolsys-storage unlock
sudo /usr/local/sbin/eufy-storage status
sudo /usr/local/sbin/eufy-storage stop
```

The unlock hook mounts the child and recreates a configured bridge so its private
bind sees the correct filesystem. Before unlock, any Docker restart attempt
fails storage validation before login or persistence. If no credentials exist,
the hook mounts storage and waits for private configuration. HA lights and other
integrations can run while cloud credential storage is unavailable.

## Encrypted backups

```bash
sudo /usr/local/sbin/eufy-storage checkpoint
```

This snapshots the child and uses **`zfs send -w`** to produce a raw encrypted
stream under `/srv/media-server-backups/eufy-encrypted-.../`. It includes a
private copy of the nonsecret guard and a SHA-256 manifest. Copy the encrypted
stream and sidecars off-host; retain the shared storage passphrase separately.
The parent's ordinary Qolsys checkpoint does not include child datasets, so use
this Eufy checkpoint explicitly after configuration/pairing or before upgrades.

Never use ordinary `zfs send`, an unencrypted tar/rsync backup, a Docker volume
export or an unencrypted HA backup of the unlocked data. Encryption of the live
filesystem does not encrypt a plaintext copy taken while it is unlocked.

Restore only into a NEW dataset and an unused private mountpoint. As root:

```bash
zfs receive -u -o canmount=noauto -o keylocation=prompt \
  -o mountpoint=/mnt/eufy-recovery recovery-pool/eufy-recovery < eufy-credentials.zfs
zfs load-key recovery-pool/eufy-recovery
zfs mount recovery-pool/eufy-recovery
```

Verify SHA-256 before receiving; check `encryption=aes-256-gcm`,
`keyformat=passphrase` and `keystatus=unavailable` before loading the key. Enter
the original shared passphrase only at the native ZFS prompt. Keep the recovered
mount private. Do not overwrite a live dataset or its guard during recovery.
