import type { Module } from "./types.js"

import { createConditionalModule } from "./conditionalModules.js"
import { detectPackageManager, isPackageInstalled } from "./modules/package.js"
import { shellQuote } from "./ssh.js"

function filesystemTypeName(testFlag: "-d" | "-f" | "-L" | "-S"): string {
  switch (testFlag) {
    case "-d": {
      return "path"
    }
    case "-f": {
      return "file"
    }
    case "-L": {
      return "symlink"
    }
    case "-S": {
      return "socket"
    }
  }
}

export function createFilesystemGuard(parameters: {
  invert: boolean
  modules: Module[]
  path: string
  testFlag: "-d" | "-f" | "-L" | "-S"
}): Module {
  const typeName = filesystemTypeName(parameters.testFlag)
  return createConditionalModule({
    async condition(ssh) {
      if (ssh == null) return false
      const exists = await ssh.test(`test ${parameters.testFlag} ${shellQuote(parameters.path)}`)
      return parameters.invert ? !exists : exists
    },
    modules: parameters.modules,
    name: `when.${typeName}${parameters.invert ? "Missing" : "Exists"}: ${parameters.path}`,
  })
}

export function createCommandGuard(
  commandName: string,
  invert: boolean,
  modules: Module[]
): Module {
  return createConditionalModule({
    async condition(ssh) {
      if (ssh == null) return false
      const exists = await ssh.test(`command -v ${shellQuote(commandName)} >/dev/null 2>&1`)
      return invert ? !exists : exists
    },
    modules,
    name: `when.command${invert ? "Missing" : "Exists"}: ${commandName}`,
  })
}

export function createPackageGuard(
  packageName: string,
  invert: boolean,
  modules: Module[]
): Module {
  return createConditionalModule({
    async condition(ssh) {
      if (ssh == null) return false
      const pm = await detectPackageManager(ssh)
      if (pm == null) return false
      const installed = await isPackageInstalled(ssh, pm, packageName)
      return invert ? !installed : installed
    },
    modules,
    name: `when.package${invert ? "Absent" : "Installed"}: ${packageName}`,
  })
}
