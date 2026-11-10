import { parseCertificateFileArgument } from "./sshCertificateConfig.js"
import { CertificateFileError } from "./sshCertificateFiles.js"
import { parseSshdConfigLine } from "./sshdConfigHelpers.js"
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

export function collectHostDirectivePaths(content: string, directive: HostDirective): string[] {
  const paths: string[] = []
  for (const line of content.split(/\r?\n/v)) {
    const parsed = parseSshdConfigLine(line)
    const keyword = parsed?.directive ?? line.trim()
    if (keyword.toLowerCase() !== directive.toLowerCase()) continue
    const path = hostDirectivePath(directive, parsed?.value ?? "")
    if (path !== null) paths.push(path)
  }
  return paths
}
