const port = Number(process.env.PORT ?? 3000);

if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  throw new Error("PORT must be a valid TCP port");
}

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port,
  databasePath: process.env.DATABASE_PATH ?? "./data/arx.sqlite",
};
