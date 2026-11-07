// Offline readiness check: no SDK login, network listener or device operation.
import { loadSecureConfig } from "../src/secure-storage.mjs";
try {
  const config = loadSecureConfig();
  config.stores.eufy.load();
  config.stores.push.load();
  config.stores.solix.load();
  config.storage.close();
  console.log("Encrypted credential storage is ready");
} catch {
  console.error("Encrypted credential storage is locked, unsafe or not configured");
  process.exitCode = 1;
}
