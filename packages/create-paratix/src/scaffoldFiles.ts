import { lstatSync, mkdirSync, type Stats, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"

import { formatCliValue } from "./cliFormat.js"
import { deriveParatixDependencyRange } from "./dependencyRange.js"
import {
  AUTO_UPGRADES_20_TEMPLATE,
  createAdminNopasswdSudoersContent,
  createServerTemplate,
  ENV_EXAMPLE_TEMPLATE,
  ESLINT_CONFIG_TEMPLATE,
  GITIGNORE_TEMPLATE,
  type InitialUserConfig,
  PRETTIER_IGNORE_TEMPLATE,
  PRETTIER_RC_TEMPLATE,
  TSCONFIG_TEMPLATE,
  UNATTENDED_UPGRADES_50_TEMPLATE,
} from "./templates.js"

type ScaffoldFileOptions = {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host: string
  initialUser: InitialUserConfig
  packageName: string
}

function lstatPathIfExists(path: string): Stats | undefined {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return lstatSync(path)
  } catch (error: unknown) {
    if (hasErrorCode(error, "ENOENT")) {
      return undefined
    }

    throw error
  }
}

function hasErrorCode(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && error.code === code
}

function throwScaffoldPathAlreadyExists(path: string): never {
  throw new Error(
    `Error: Scaffold file ${formatCliValue(path)} already exists; refusing to overwrite it.`
  )
}

function assertWritableScaffoldDirectory(path: string): void {
  // Atomic create-or-detect: mkdirSync with recursive:false either creates the
  // directory or throws EEXIST. After either outcome, we lstat the path and
  // reject symlinks or non-directories. Replacing the prior
  // lstat -> mkdir -> lstat sequence closes the TOCTOU window in which an
  // attacker could swap the path for a symlink between the existence check
  // and the directory creation.
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    mkdirSync(path, { recursive: false })
  } catch (error: unknown) {
    if (!hasErrorCode(error, "EEXIST")) {
      throw error
    }
  }

  const stats = lstatPathIfExists(path)
  if (stats == null || !stats.isDirectory() || stats.isSymbolicLink()) {
    throwScaffoldPathAlreadyExists(path)
  }
}

function writeManagedScaffoldFile(
  projectDirectory: string,
  relativePath: string,
  content: string
): void {
  const targetPath = join(projectDirectory, relativePath)
  const targetStats = lstatPathIfExists(targetPath)

  if (targetStats != null) {
    throwScaffoldPathAlreadyExists(targetPath)
  }

  assertWritableScaffoldDirectory(dirname(targetPath))

  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    writeFileSync(targetPath, content, { flag: "wx" })
  } catch (error: unknown) {
    if (hasErrorCode(error, "EEXIST")) {
      throwScaffoldPathAlreadyExists(targetPath)
    }

    throw error
  }
}

function writeSharedScaffoldFiles(projectDirectory: string): void {
  writeManagedScaffoldFile(projectDirectory, "tsconfig.json", TSCONFIG_TEMPLATE)
  writeManagedScaffoldFile(projectDirectory, ".gitignore", GITIGNORE_TEMPLATE)
  writeManagedScaffoldFile(projectDirectory, ".prettierrc", PRETTIER_RC_TEMPLATE)
  writeManagedScaffoldFile(projectDirectory, ".prettierignore", PRETTIER_IGNORE_TEMPLATE)
  writeManagedScaffoldFile(projectDirectory, "eslint.config.ts", ESLINT_CONFIG_TEMPLATE)
  writeManagedScaffoldFile(projectDirectory, ".env.example", ENV_EXAMPLE_TEMPLATE)
}

function writeScaffoldSupportFiles(projectDirectory: string, initialUser: InitialUserConfig): void {
  writeManagedScaffoldFile(projectDirectory, join("files", ".gitkeep"), "")
  writeManagedScaffoldFile(
    projectDirectory,
    join("files", "20auto-upgrades"),
    AUTO_UPGRADES_20_TEMPLATE
  )
  writeManagedScaffoldFile(
    projectDirectory,
    join("files", "50unattended-upgrades"),
    UNATTENDED_UPGRADES_50_TEMPLATE
  )
  if (initialUser.kind !== "root") return
  writeManagedScaffoldFile(
    projectDirectory,
    join("files", "admin-nopasswd-sudoers"),
    createAdminNopasswdSudoersContent("paratix")
  )
}

export function writeScaffoldFiles(
  projectDirectory: string,
  { adminPublicKey, expectedHostFingerprint, host, initialUser, packageName }: ScaffoldFileOptions
): void {
  // R-0000828: the previous implementation pre-walked the list of managed
  // scaffold paths with `lstatPathIfExists` and aborted if any of them
  // already existed. That probe was a pure TOCTOU artefact: the actual
  // writes downstream are already safe because (1) `assertWritableScaffold
  // Directory` uses `mkdirSync` with `recursive: false` plus a follow-up
  // lstat that rejects symlinks and non-directories, and (2)
  // `writeManagedScaffoldFile` opens its target with `flag: "wx"` and maps
  // `EEXIST` to a clear refusal. The pre-walk therefore only narrowed the
  // race window between probe and write, while giving no real protection
  // against an attacker who can race file creation. Removing it keeps the
  // already-atomic guarantees and avoids advertising a check that does not
  // actually hold.
  assertWritableScaffoldDirectory(projectDirectory)
  assertWritableScaffoldDirectory(join(projectDirectory, "files"))

  const packageJson = {
    dependencies: {
      paratix: deriveParatixDependencyRange(),
    },
    devDependencies: {
      "@types/node": "^24.13.3",
      // TypeScript 7 is a native port that ships no compiler API before 7.1,
      // while typescript-eslint reads that API through eslint-config-setup.
      // Aliasing "typescript" onto the 6.x compatibility package keeps that
      // working and leaves the "tsc" binary to the 7.x entry below, so the two
      // never collide.
      "@typescript/native": "npm:typescript@^7.0.2",
      eslint: "^10.8.0",
      "eslint-config-setup": "^0.5.2",
      jiti: "^2.7.0",
      prettier: "^3.9.6",
      tsx: "^4.23.1",
      typescript: "npm:@typescript/typescript6@^6.0.2",
    },
    engines: {
      node: ">=24.0.0",
    },
    name: packageName,
    private: true,
    scripts: {
      apply: "paratix apply server.ts",
      "apply:dry": "paratix apply server.ts --dry-run",
      "apply:first-run": "paratix apply server.ts --first-run",
      "apply:first-run:dry": "paratix apply server.ts --dry-run --first-run",
      "format:check": "prettier --check .",
      "format:fix": "prettier --write .",
      lint: "eslint .",
      typecheck: "tsc --noEmit",
    },
    type: "module",
  }

  writeManagedScaffoldFile(
    projectDirectory,
    "package.json",
    `${JSON.stringify(packageJson, null, 2)}\n`
  )
  writeManagedScaffoldFile(
    projectDirectory,
    "server.ts",
    createServerTemplate({ adminPublicKey, expectedHostFingerprint, host, initialUser })
  )
  writeSharedScaffoldFiles(projectDirectory)
  writeScaffoldSupportFiles(projectDirectory, initialUser)
}
