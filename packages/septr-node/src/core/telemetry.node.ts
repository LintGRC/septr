/**
 * Node-only telemetry bootstrap. Imported dynamically (and only on Node
 * runtimes) from core/telemetry.ts — never from edge-runtime bundles, where
 * fs/path/node:module are unavailable.
 */
import { warnEnvVsDotenv } from "./env-check"

export function nodeTelemetryBootstrap(): void {
  warnEnvVsDotenv(process.env.SEPTR_API_KEY || process.env.VS_API_KEY)
}
