import { posix } from "node:path"

import type { SshConnection } from "../types.js"

import { shellQuote, validateMktempPath } from "../ssh.js"
import {
  certificateCommand,
  type CertificateFile,
  CertificateFileError,
  certificateFileMatches,
  type CertificateFileState,
  contentHash,
  inspectCertificateFile,
  parentPaths,
  sameState,
} from "./sshCertificateFiles.js"

const REGULAR_MODE = "644 0 0"

type Snapshot = {
  backup?: string
  expected: CertificateFileState
  file: CertificateFile
  touched: boolean
}

/** Owns only files explicitly passed to write/remove, and newly created parents. */
export class CertificateFilesTransaction {
  private readonly directories: string[] = []
  private readonly retained = new Set<string>()
  private readonly snapshots: Snapshot[] = []
  private readonly staging: string[] = []
  public constructor(private readonly ssh: SshConnection) {}

  public async cleanup(): Promise<string[]> {
    const failures: string[] = []
    for (const directory of this.staging) {
      if (this.retained.has(directory)) continue
      try {
        // eslint-disable-next-line no-await-in-loop -- collect every cleanup failure
        await certificateCommand(this.ssh, `rm -rf -- ${shellQuote(directory)}`)
      } catch (error) {
        failures.push(`${directory}: ${String(error)}`)
      }
    }
    return failures
  }

  public async remove(file: CertificateFile): Promise<void> {
    if (file.original === null) return
    const snapshot = await this.snapshot(file)
    await this.assertOriginalUnchanged(snapshot)
    snapshot.expected = null
    snapshot.touched = true
    await certificateCommand(this.ssh, `rm -- ${shellQuote(file.path)}`)
  }

  public async rollback(): Promise<string[]> {
    const failures: string[] = []
    for (const snapshot of [...this.snapshots].reverse()) {
      if (!snapshot.touched) continue
      try {
        // eslint-disable-next-line no-await-in-loop -- rollback is ordered in reverse mutation order
        await this.restore(snapshot)
      } catch (error) {
        failures.push(this.retainFailedBackup(snapshot, error))
      }
    }
    failures.push(...(await this.cleanup()))
    for (const directory of [...this.directories].reverse()) {
      try {
        // eslint-disable-next-line no-await-in-loop -- remove newly created parents from leaf to root
        await certificateCommand(
          this.ssh,
          `if [ -e ${shellQuote(directory)} ]; then rmdir -- ${shellQuote(directory)}; fi`
        )
      } catch (error) {
        failures.push(`${directory}: ${String(error)}`)
      }
    }
    return failures
  }

  public async write(file: CertificateFile): Promise<void> {
    if (certificateFileMatches(file)) return
    const snapshot = await this.snapshot(file)
    const directory = this.staging.at(-1)
    if (directory === undefined || file.content === undefined)
      throw new CertificateFileError("Missing staged content")
    const temporary = `${directory}/candidate`
    await this.ssh.writeFile(temporary, file.content, { mode: "0600" })
    await certificateCommand(
      this.ssh,
      `chown 0:0 -- ${shellQuote(temporary)} && chmod 0644 -- ${shellQuote(temporary)}`
    )
    await this.assertOriginalUnchanged(snapshot)
    snapshot.expected = { hash: contentHash(file.content), metadata: REGULAR_MODE }
    snapshot.touched = true
    await certificateCommand(this.ssh, `mv -T -- ${shellQuote(temporary)} ${shellQuote(file.path)}`)
    if (!sameState(await inspectCertificateFile(this.ssh, file.path), snapshot.expected)) {
      throw new CertificateFileError(`Published file verification failed: ${file.path}`)
    }
  }

  private async assertOriginalUnchanged(snapshot: Snapshot): Promise<void> {
    const current = await inspectCertificateFile(this.ssh, snapshot.file.path)
    if (!sameState(current, snapshot.file.original))
      throw new CertificateFileError(`Concurrent modification: ${snapshot.file.path}`)
  }

  private async prepareParents(path: string): Promise<void> {
    for (const parent of parentPaths(path)) {
      // eslint-disable-next-line no-await-in-loop -- parents are created in order
      if (await this.ssh.test(`[ -e ${shellQuote(parent)} ]`)) continue
      this.directories.push(parent)
      // eslint-disable-next-line no-await-in-loop -- parents are created in order
      await certificateCommand(
        this.ssh,
        `umask 022; mkdir -- ${shellQuote(parent)} && chown 0:0 -- ${shellQuote(parent)} && chmod 0755 -- ${shellQuote(parent)}`
      )
    }
  }

  private async restore(snapshot: Snapshot): Promise<void> {
    const current = await inspectCertificateFile(this.ssh, snapshot.file.path)
    if (sameState(current, snapshot.file.original)) return
    if (!sameState(current, snapshot.expected)) {
      throw new CertificateFileError(
        "Concurrent modification prevents safe rollback; backup retained"
      )
    }
    if (snapshot.backup === undefined) {
      await certificateCommand(this.ssh, `rm -f -- ${shellQuote(snapshot.file.path)}`)
    } else {
      await certificateCommand(
        this.ssh,
        `mv -T -- ${shellQuote(snapshot.backup)} ${shellQuote(snapshot.file.path)}`
      )
    }
    if (
      !sameState(await inspectCertificateFile(this.ssh, snapshot.file.path), snapshot.file.original)
    ) {
      throw new CertificateFileError("Restored file content or metadata did not match snapshot")
    }
  }

  private retainFailedBackup(snapshot: Snapshot, error: unknown): string {
    if (snapshot.backup !== undefined) this.retained.add(posix.dirname(snapshot.backup))
    return `${snapshot.file.path}: ${String(error)}; backup: ${snapshot.backup ?? "no previous file"}`
  }

  private async snapshot(file: CertificateFile): Promise<Snapshot> {
    if (this.snapshots.some((entry) => entry.file.path === file.path))
      throw new CertificateFileError(`File already enrolled in transaction: ${file.path}`)
    const current = await inspectCertificateFile(this.ssh, file.path, { preserve: file.preserve })
    if (!sameState(current, file.original))
      throw new CertificateFileError(`Concurrent modification: ${file.path}`)
    await this.prepareParents(file.path)
    const parent = posix.dirname(file.path)
    const directory = validateMktempPath(
      parent,
      await certificateCommand(
        this.ssh,
        `mktemp -d -p ${shellQuote(parent)} -- '.paratix-certificate.XXXXXX'`
      ),
      ".paratix-certificate"
    )
    this.staging.push(directory)
    const backup = file.original === null ? undefined : `${directory}/original`
    if (backup !== undefined) {
      await certificateCommand(
        this.ssh,
        `cp -p --no-dereference -- ${shellQuote(file.path)} ${shellQuote(backup)}`
      )
      if (!sameState(await inspectCertificateFile(this.ssh, backup), file.original)) {
        throw new CertificateFileError(`Backup verification failed: ${file.path}`)
      }
    }
    const snapshot: Snapshot = { backup, expected: file.original, file, touched: false }
    this.snapshots.push(snapshot)
    return snapshot
  }
}
