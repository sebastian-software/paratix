import { parseCertificateFileArgument } from "./sshCertificateConfig.js"
import { CertificateFileError } from "./sshCertificateFiles.js"
import { HostCertificateError } from "./sshSignerProcess.js"

type HostDirective = "HostCertificate" | "HostKey"

export function hostDirectivePath(directive: HostDirective, value: string): null | string {
  try {
    const token = parseCertificateFileArgument(directive, value)
    return directive === "HostCertificate" && token.raw === "none" ? null : token.value
  } catch (error) {
    if (error instanceof CertificateFileError) throw new HostCertificateError(error.message)
    throw error
  }
}

export function collectEffectiveHostDirectivePaths(
  content: string,
  directive: HostDirective
): string[] {
  const paths: string[] = []
  for (const line of content.split(/\r?\n/v)) {
    const separator = line.search(/[ \t]|$/v)
    const keyword = line.slice(0, separator)
    if (keyword.toLowerCase() !== directive.toLowerCase()) continue
    const path = line.slice(separator + 1)
    if (path.length === 0)
      throw new HostCertificateError(`Cannot safely resolve sshd ${directive}; correct it manually`)
    if (directive !== "HostCertificate" || path !== "none") paths.push(path)
  }
  return paths
}
