import { buildServer } from "./api/server";

const app = buildServer();

const port = Number(process.env.PORT ?? 3000);

try {
  await app.listen({
    port,
    host: "0.0.0.0",
  });

  console.log(`Arx Policy Engine running on port ${port}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
