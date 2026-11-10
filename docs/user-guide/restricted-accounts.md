# Create a read-only diagnostic account without sudo

This recipe builds a login for a monitoring or support person who may run exactly one
read-only script on a server: no shell, no sudo, no forwarding, no terminal. Two layers enforce
this. A restricted `authorized_keys` entry limits what the key can do, and an sshd `Match` block
limits what the account can do however it authenticates. The
[`ssh.authorizedKeys`](../../packages/paratix/llm-guide.md#sshauthorizedkeys) and
[`sshd.match`](../../packages/paratix/llm-guide.md#sshdmatch) references list every option.

## Prerequisites

- The target's `/etc/ssh/sshd_config` loads `Include /etc/ssh/sshd_config.d/*.conf` at top
  level, before its first `Match` line. Debian and Ubuntu ship it that way. Paratix never adds
  this line, and `sshd.match` fails without it.
- The account that Paratix connects as (`ssh.user`) is not the restricted account, and not a
  member of a group you match. `sshd.match` refuses criteria that match the connection user to
  prevent a later run from locking itself out.
- The account must not be locked for public-key logins. `user.present` without `password` leaves
  the new account with a locked password field (typically `!`). Debian and Ubuntu default to
  `UsePAM yes`, where this is fine. With `UsePAM no`, OpenSSH refuses public-key logins for locked
  accounts; give the account a non-locking placeholder instead, for example
  `user.present(account, { shell: "/bin/sh", password: "*" })`. `*` is no valid hash, so it still
  allows no password login, but it does not mark the account as locked.
- The target provides `setpriv` or `runuser` (both from util-linux, installed on Debian and
  Ubuntu). `ssh.authorizedKeys` writes the restricted account's `~/.ssh` as that account and fails
  without one of them. The account's home directory must exist before the key is managed;
  `user.present` creates it.
- The forced-command script exists on the controller, for example `files/ops-ro-shell`. Keep it
  minimal: it runs for every login of that key, and the client's requested command reaches it
  only as the `SSH_ORIGINAL_COMMAND` environment variable.

## Playbook

```typescript
import { server } from "paratix"
import { file, ssh, sshd, user } from "paratix/modules"

const account = "ops-ro"
const script = "/usr/local/bin/ops-ro-shell"
const publicKey = "ssh-ed25519 AAAA... ops-ro@example"

export default server({
  name: "diagnostic-host",
  host: "203.0.113.10",
  ssh: { user: "root", ports: [22], privateKey: "~/.ssh/admin" },
  run: [
    user.present(account, { shell: "/bin/sh" }),
    file.copy(script, "./files/ops-ro-shell", { mode: "0755", owner: "root:root" }),
    ssh.authorizedKeys(account, publicKey, {
      options: { restrict: true, command: script },
    }),
    sshd.match(
      account,
      { user: account },
      {
        DisableForwarding: "yes",
        ForceCommand: script,
        PermitTTY: "no",
        PermitUserRC: "no",
      }
    ),
  ],
})
```

The account needs a working login shell path so that sshd can start the forced command through
it, but the key and the `Match` block never let the client choose a command.

## Why this order

1. `user.present` comes first. `ssh.authorizedKeys` needs the account and its primary group, and
   `sshd.match` needs the account for its effect check: `verifyUser` defaults to the first `user`
   criterion, and apply fails when that user does not exist. In a dry-run before the first apply,
   both modules report `changed` instead of failing, and `sshd.match` marks its effect check as
   pending.
2. The script is installed before any login can reach it, and owned by root so that the account
   cannot change what it runs.
3. The key comes before the `Match` block, so the key is already restricted at the moment the
   daemon starts applying account-wide rules. Either order is safe for the target because
   `restrict` and the `Match` block each restrict on their own.

`restrict` disables port, agent and X11 forwarding, PTY allocation and `~/.ssh/rc` for that key;
`command` replaces whatever the client asks to run. The `Match` block repeats the intent on the
server side with `DisableForwarding yes`, `PermitTTY no`, `PermitUserRC no` and `ForceCommand`,
so a second key added later by hand to the account's `authorized_keys` is restricted too.

## What the effect check proves

Before the drop-in is published, `sshd.match` copies the full configuration tree, inserts the
candidate, and runs `sshd -t` on the result. It then runs `sshd -T -C
user=ops-ro,host=paratix-verify.invalid,addr=192.0.2.1` and compares each declared directive with
the value sshd prints. After publishing it checks again against the live files and only then
reloads sshd. A failure at any step restores the previous state.

If a run is interrupted after the drop-in changed but before sshd confirmed the reload, the
`/var/lib/paratix/sshd-match-pending-<name>` state file stays behind. Run the same playbook again:
`check` reports `needs-apply` until a later apply repeats the safety checks, reloads sshd and removes
the file. A retry therefore fixes the mismatch even when the drop-in on disk is already correct.

This proves that, for that user and that placeholder connection, the effective values are the
ones you declared, including when another drop-in would have set the directive first (the check
fails and names the directive). It does not prove:

- the same result for `Match Address` or `Match Host` blocks that apply to real client
  connections but not to the placeholder address;
- the result for other accounts matched by the criteria (further `user` entries or `group`
  members), for example when they have their own earlier `Match` blocks;
- that the forced script itself is safe or read-only. Review it like code that runs on
  every login.

If the check reports that an earlier value wins, rename the drop-in so that it sorts first
(sshd reads `sshd_config.d` files in name order and uses the first value it obtains), or adjust
the order of the `Match` blocks.

## Several accounts through a group

To restrict a whole group, use `{ group: "ops-ro" }`. A `group` criterion needs `verifyUser`:

```typescript
sshd.match(
  "ops-ro-group",
  { group: "ops-ro" },
  { DisableForwarding: "yes", PermitTTY: "no" },
  { verifyUser: "alice-ro" }
)
```

Apply fails unless the verify user is a member of the group; a dry-run before the membership
exists reports `changed` with a pending effect check, like a missing user. The effect check covers
only that user.

## Remove the account

Remove the key first, then the account, then the restrictions, and the script last. Declare
removal in a playbook that replaces the setup above:

```typescript
run: [
  ssh.authorizedKeys(account, publicKey, { state: "absent" }),
  user.absent(account, { removeHome: true }),
  sshd.match(account, { user: account }, {}, { state: "absent" }),
  file.absent(script),
]
```

This order leaves no window in which a key is accepted without the `Match` block: while the
account exists, the block still restricts every key, including one added to `authorized_keys` by
hand, and the block is removed only after the account is gone. `sshd.match` with `absent` needs
neither the verify user nor the top-level Include, so it still works after `user.absent`. The
script goes last because the `Match` block and the key name it as their forced command.

`sshd.match` with `state: "absent"` validates the tree without the drop-in, removes
`/etc/ssh/sshd_config.d/ops-ro.conf` and reloads sshd. Pass the same criteria and name as for the
setup; the directives may be empty because they are not compared when removing. It removes only a
file that carries the Paratix marker for this name; a foreign file with the same name makes the
module fail. The lockout guard also applies to removal: if you installed the block with
`allowConnectionUser: true`, pass it again with `state: "absent"`. `ssh.authorizedKeys` with
`absent` removes every line of that key, whatever its options or comment, and leaves other lines
alone.
`user.absent` fails while the account has running processes. End its sessions first.

## See also

- [Migration notes](./migration.md#unreleased) for the changed `ssh.authorizedKeys` identity rules.
- [`ssh.trustedUserCa`](./README.md#configure-server-side-user-certificates), which manages the
  directives that `sshd.match` rejects.
