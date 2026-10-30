// SFTP against the real sshd: H4 (mode 0600 on an existing and a fresh
// file, 32 MiB intact), streaming read, and the numeric status of failed
// requests (SFTP_STATUS with `sftpStatus`).
//
// Which request fails, with OpenSSH's sftp-server:
// - missing file: OPEN for reading fails with NO_SUCH_FILE (2);
// - missing permissions: sftp-server opens the file with open(2), so EACCES
//   surfaces at OPEN as PERMISSION_DENIED (3) and no WRITE is ever sent;
// - full file system: OPEN succeeds and a WRITE fails with ENOSPC, which
//   sftp-server reports as FAILURE (4).
// OpenSSH cannot be made to fail a CLOSE (close(2) on a local file system
// does not fail in practice), nor to deny a WRITE on an already open handle
// for missing permissions (permissions are checked once, at open(2)). So the
// numeric status of a failed CLOSE stays proven by the B1 in-process unit
// test "keeps the numeric status of a failed CLOSE" (test/sftp.test.mjs,
// in-process ssh2 server), and missing permissions are proven here at OPEN
// (PERMISSION_DENIED, 3).
import assert from "node:assert/strict"
import { randomBytes } from "node:crypto"
import { Readable } from "node:stream"
import { pipeline } from "node:stream/promises"
import { after, before, describe } from "node:test"

import { collect } from "../helpers/binding.mjs"
import { sha256 } from "../helpers/server.mjs"
import { check, descriptor, fixtures, hardProof } from "./lib/context.mjs"
import { FULL_FS_PATH } from "./lib/docker-target.mjs"
import { connectWithKeyFile, run, SHA256_STDIN } from "./lib/remote.mjs"

const MIB = 1024 * 1024
const CHUNK = 64 * 1024
const NO_SUCH_FILE = 2
const PERMISSION_DENIED = 3
const FAILURE = 4

/**
 * @param data the content
 * @returns 64 KiB views of it
 */
function chunksOf(data) {
  const chunks = []
  for (let offset = 0; offset < data.length; offset += CHUNK) {
    chunks.push(data.subarray(offset, offset + CHUNK))
  }
  return chunks
}

/**
 * @param stream an SFTP write stream
 * @param data content, written in 64 KiB chunks
 * @returns resolves once the remote file is closed
 */
function writeInto(stream, data) {
  return pipeline(Readable.from(chunksOf(data)), stream)
}

describe("sftp", () => {
  /** @type {import("../../index.js").Session | undefined} */
  let session
  /** @type {import("../../index.js").SftpSession | undefined} */
  let sftp
  let dir = ""

  before(async () => {
    if (descriptor.unavailable !== null) return
    session = await connectWithKeyFile(fixtures().keys.ed25519)
    sftp = await session.sftp()
    const created = await run(session, "mktemp -d")
    dir = created.stdout.trim()
    assert.ok(dir.startsWith("/"), `mktemp -d printed ${dir}`)
  })
  after(async () => {
    if (!session) return
    await sftp?.end()
    if (dir) await run(session, `chmod -R u+w '${dir}'; rm -rf '${dir}'`)
    await session.close()
  })

  /** @returns the shared session and its SFTP channel */
  const open = () => ({
    sftp: /** @type {import("../../index.js").SftpSession} */ (sftp),
    ssh: /** @type {import("../../index.js").Session} */ (session),
  })

  hardProof(
    {
      id: "H4-sftp-mode-0600",
      name: "32 MiB with mode 0600 into an existing 0644 file, and a fresh file",
    },
    async (t) => {
      const { sftp: files, ssh } = open()
      const existing = `${dir}/existing.bin`
      const fresh = `${dir}/fresh.bin`
      const created = await run(
        ssh,
        `umask 022; echo old > '${existing}'; find '${existing}' -perm 644`
      )
      assert.equal(created.stdout.trim(), existing, "the existing file starts with mode 0644")

      const data = randomBytes(32 * MIB)
      const expected = sha256(data)
      const started = Date.now()
      await writeInto(files.createWriteStream(existing, { mode: 0o600 }), data)
      t.diagnostic(`32 MiB written in ${Date.now() - started} ms`)
      await writeInto(files.createWriteStream(fresh, { mode: 0o600 }), Buffer.from("fresh"))

      const modes = await run(ssh, `find '${dir}' -name '*.bin' -perm 600 | sort`)
      assert.deepEqual(modes.stdout.trim().split("\n"), [existing, fresh])
      const size = await run(ssh, `wc -c < '${existing}'`)
      assert.equal(Number(size.stdout.trim()), data.length)
      const summed = await run(ssh, `(${SHA256_STDIN}) < '${existing}'`)
      assert.equal(summed.stdout.split(" ")[0], expected)
    }
  )

  check("reads a file as a stream with the same content", async () => {
    const { sftp: files, ssh } = open()
    const path = `${dir}/read.bin`
    const data = randomBytes(5 * MIB + 17)
    // Hash first: the binding zero-fills every Buffer written to stdin.
    const expected = sha256(data)
    const written = await run(ssh, `cat > '${path}'`, data)
    assert.equal(written.code, 0, written.stderr)
    const back = await collect(files.createReadStream(path))
    assert.equal(back.length, 5 * MIB + 17)
    assert.equal(sha256(back), expected)
  })

  check("reports a missing file as SFTP_STATUS NO_SUCH_FILE", async () => {
    await assert.rejects(collect(open().sftp.createReadStream(`${dir}/missing`)), {
      code: "SFTP_STATUS",
      sftpStatus: NO_SUCH_FILE,
    })
  })

  check(
    "reports missing write permission as SFTP_STATUS PERMISSION_DENIED (at OPEN)",
    async () => {
      const { sftp: files, ssh } = open()
      const prepared = await run(
        ssh,
        `mkdir '${dir}/locked' && chmod 500 '${dir}/locked' && printf x > '${dir}/ro' && chmod 444 '${dir}/ro'`
      )
      assert.equal(prepared.code, 0, prepared.stderr)
      for (const path of [`${dir}/locked/new.bin`, `${dir}/ro`]) {
        // eslint-disable-next-line no-await-in-loop -- one request at a time
        await assert.rejects(writeInto(files.createWriteStream(path), randomBytes(CHUNK)), {
          code: "SFTP_STATUS",
          sftpStatus: PERMISSION_DENIED,
        })
      }
    },
    { needs: ["sshd", "non-root"] }
  )

  check(
    "reports a WRITE on a full file system as SFTP_STATUS FAILURE (tmpfs)",
    async () => {
      const { sftp: files, ssh } = open()
      const path = `${FULL_FS_PATH}/fill.bin`
      try {
        await assert.rejects(writeInto(files.createWriteStream(path), randomBytes(4 * MIB)), {
          code: "SFTP_STATUS",
          sftpStatus: FAILURE,
        })
      } finally {
        await run(ssh, `rm -f '${path}'`)
      }
    },
    { needs: ["sshd", "tmpfs"] }
  )

  check(
    "reports a WRITE that fails with ENOSPC as SFTP_STATUS FAILURE (/dev/full)",
    async () => {
      await assert.rejects(
        writeInto(open().sftp.createWriteStream("/dev/full"), randomBytes(4 * CHUNK)),
        {
          code: "SFTP_STATUS",
          sftpStatus: FAILURE,
        }
      )
    },
    { needs: ["sshd", "dev-full"] }
  )
})
