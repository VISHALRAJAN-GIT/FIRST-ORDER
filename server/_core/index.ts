import "dotenv/config";
import express, { type Express } from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { registerOAuthRoutes } from "./oauth";
import { registerStorageProxy } from "./storageProxy";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { subscribeInventory } from "../events";
import { expireReservations } from "../services/bookingService";
import { getDb } from "../db";
import { securityRateLimitMiddleware } from "../securityMiddleware";

function isPortAvailable(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.listen(port, () => server.close(() => resolve(true)));
    server.on("error", () => resolve(false));
  });
}

async function findAvailablePort(startPort = 3000): Promise<number> {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) return port;
  }
  throw new Error(`No available port found starting from ${startPort}`);
}

/** Creates the API application without binding a port or serving frontend assets. */
export function createApp(): Express {
  const app = express();
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ limit: "50mb", extended: true }));
  registerStorageProxy(app);
  registerOAuthRoutes(app);
  app.get("/api/health", (_req, res) => res.json({ ok: true, service: "tixify" }));
  app.get("/api/events/:eventId/stream", (req, res) => {
    const eventId = Number(req.params.eventId);
    if (!Number.isInteger(eventId) || eventId <= 0) return res.status(400).end();
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.write(`event: connected\ndata: ${JSON.stringify({ eventId })}\n\n`);
    const unsubscribe = subscribeInventory(eventId, payload => res.write(`event: inventory\ndata: ${JSON.stringify(payload)}\n\n`));
    const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), 25_000);
    req.on("close", () => { clearInterval(heartbeat); unsubscribe(); res.end(); });
  });
  app.post("/api/scheduled/expire-reservations", async (_req, res) => {
    try {
      const db = await getDb();
      if (!db) return res.status(503).json({ success: false, error: { code: "DATABASE_UNAVAILABLE" } });
      return res.json({ success: true, expired: await expireReservations(db) });
    } catch {
      return res.status(500).json({ success: false, error: { code: "EXPIRATION_FAILED" } });
    }
  });
  app.use("/api/trpc", securityRateLimitMiddleware, createExpressMiddleware({ router: appRouter, createContext }));
  return app;
}

async function startServer() {
  const app = createApp();
  const server = createServer(app);
  if (process.env.NODE_ENV === "development") await setupVite(app, server);
  else serveStatic(app);
  const preferredPort = parseInt(process.env.PORT || "3000", 10);
  const port = await findAvailablePort(preferredPort);
  if (port !== preferredPort) console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  server.listen(port, () => console.log(`Server running on http://localhost:${port}/`));
}

if (process.env.VERCEL !== "1") startServer().catch(console.error);
