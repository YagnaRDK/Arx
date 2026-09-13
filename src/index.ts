import { buildServer } from "./api/server";
import { env } from "./config/env";
import { authorizationKey } from "./crypto/authorization-key";

const app = await buildServer();

try {
  await app.listen({ port: env.port, host: "0.0.0.0" });

  const banner = [
    "",
    "  Arx — the agent proposes, Arx authorizes, the device signs.",
    "",
    `  listening      http://localhost:${env.port}`,
    `  database       ${env.databasePath}`,
    `  signer mode    ${env.signerMode}${env.signerMode === "mock" ? "  (MOCK — output is not a blockchain signature)" : ""}`,
    `  price oracle   ${env.priceOracleMode}`,
    `  auth key       ${authorizationKey.keyId}${authorizationKey.ephemeral ? "  (ephemeral — approvals will not survive a restart)" : ""}`,
    `  control plane  ${env.adminToken ? "protected" : "OPEN — set ARX_ADMIN_TOKEN before exposing this port"}`,
    `  agent auth     ${env.requireAgentAuth ? "required" : "optional"}`,
    "",
  ].join("\n");

  console.log(banner);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}

/** Close the server cleanly so the expiry sweeper's interval does not linger. */
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void app.close().then(() => process.exit(0));
  });
}
