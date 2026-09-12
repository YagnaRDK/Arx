import { buildServer } from "./api/server";
import { env } from "./config/env";

const app = buildServer();

try {
  await app.listen({
    port: env.port,
    host: "0.0.0.0",
  });

  console.log(`Arx Policy Engine running on port ${env.port}`);
  console.log(`Database: ${env.databasePath}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
