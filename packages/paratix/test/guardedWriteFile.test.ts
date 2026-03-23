import { describe, expect, it, vi } from "vitest"

import { guardedWriteFile } from "../src/types.js"
import { createMockSsh } from "./helpers/mockSsh.js"

describe("guardedWriteFile", () => {
  it("writes the file when originalContent matches the current file content", async () => {
    // Arrange
    const remotePath = "/etc/app.conf"
    const mode = "0644"
    const originalContent = "key=value"
    const newContent = "key=updated"

    const ssh = createMockSsh()
    // Directly mock readFile to return the exact originalContent without any
    // trimming side effects from the internal output() implementation.
    vi.spyOn(ssh, "readFile").mockResolvedValue(originalContent)
    const writeFileSpy = vi.spyOn(ssh, "writeFile")

    // Act
    await guardedWriteFile(ssh, { mode, newContent, originalContent, remotePath })

    // Assert
    expect(writeFileSpy).toHaveBeenCalledOnce()
    expect(writeFileSpy).toHaveBeenCalledWith(remotePath, newContent, { mode })
  })

  it("passes the mode option to writeFile when provided", async () => {
    // Arrange
    const remotePath = "/etc/secret.conf"
    const originalContent = "secret=abc"
    const newContent = "secret=xyz"
    const mode = "0600"

    const ssh = createMockSsh()
    vi.spyOn(ssh, "readFile").mockResolvedValue(originalContent)
    const writeFileSpy = vi.spyOn(ssh, "writeFile")

    // Act
    await guardedWriteFile(ssh, { mode, newContent, originalContent, remotePath })

    // Assert
    expect(writeFileSpy).toHaveBeenCalledOnce()
    expect(writeFileSpy).toHaveBeenCalledWith(remotePath, newContent, { mode })
  })

  it("throws when the file content has changed between read and write (TOCTOU)", async () => {
    // Arrange: simulate a concurrent modification — the file on disk now
    // contains different content than what was originally read.
    const remotePath = "/etc/app.conf"
    const mode = "0644"
    const originalContent = "key=value\n"
    const concurrentlyModifiedContent = "key=modified-by-another-process\n"
    const newContent = "key=updated\n"

    const ssh = createMockSsh()
    // Override readFile to return a different content than originalContent,
    // simulating a write by another process between our read and write.
    vi.spyOn(ssh, "readFile").mockResolvedValue(concurrentlyModifiedContent)

    // Act + Assert
    await expect(
      guardedWriteFile(ssh, { mode, newContent, originalContent, remotePath })
    ).rejects.toThrow(/Concurrent modification/v)
  })

  it("includes the file path in the error message on concurrent modification", async () => {
    // Arrange
    const remotePath = "/etc/nginx/nginx.conf"
    const mode = "0644"
    const originalContent = "worker_processes 1;\n"
    const concurrentlyModifiedContent = "worker_processes 4;\n"
    const newContent = "worker_processes 2;\n"

    const ssh = createMockSsh()
    vi.spyOn(ssh, "readFile").mockResolvedValue(concurrentlyModifiedContent)

    // Act + Assert
    await expect(
      guardedWriteFile(ssh, { mode, newContent, originalContent, remotePath })
    ).rejects.toThrow(remotePath)
  })

  it("includes 'Concurrent modification' in the error message", async () => {
    // Arrange
    const remotePath = "/etc/app.conf"
    const mode = "0644"
    const originalContent = "v1\n"
    const concurrentlyModifiedContent = "v2\n"
    const newContent = "v3\n"

    const ssh = createMockSsh()
    vi.spyOn(ssh, "readFile").mockResolvedValue(concurrentlyModifiedContent)

    // Act + Assert
    await expect(
      guardedWriteFile(ssh, { mode, newContent, originalContent, remotePath })
    ).rejects.toThrow("Concurrent modification")
  })

  it("does not call writeFile when concurrent modification is detected", async () => {
    // Arrange
    const remotePath = "/etc/app.conf"
    const mode = "0644"
    const originalContent = "original\n"
    const concurrentlyModifiedContent = "changed\n"
    const newContent = "new\n"

    const ssh = createMockSsh()
    vi.spyOn(ssh, "readFile").mockResolvedValue(concurrentlyModifiedContent)
    const writeFileSpy = vi.spyOn(ssh, "writeFile")

    // Act
    await expect(
      guardedWriteFile(ssh, { mode, newContent, originalContent, remotePath })
    ).rejects.toThrow(/Concurrent modification/v)

    // Assert: writeFile must never be called when the guard triggers
    expect(writeFileSpy).not.toHaveBeenCalled()
  })
})
