/**
 * Resolve a file inside a `septr-checks/` directory by walking up from this
 * module's directory. Works for the source layout (src/core -> packages/
 * septr-checks), the bundled dist layout (dist/cli.js -> packages/septr-checks),
 * and installed npm packages (node_modules/septr/septr-checks, shipped at
 * package root by the build).
 */
import { existsSync } from "fs"
import { dirname, join } from "path"
import { fileURLToPath } from "url"

const MODULE_DIR = dirname(fileURLToPath(import.meta.url))
const MAX_LEVELS = 6

export function findChecksFile(name: string): string {
  let dir = MODULE_DIR
  for (let level = 0; level <= MAX_LEVELS; level++) {
    const candidate = join(dir, "septr-checks", name)
    if (existsSync(candidate)) return candidate
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  throw new Error(
    `septr-checks/${name} not found (searched upward from ${MODULE_DIR}); reinstall the package or restore the septr-checks directory`,
  )
}
