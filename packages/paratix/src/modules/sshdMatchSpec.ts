/**
 * Literal account criteria of one `sshd.match` block. At least one of `user`
 * and `group` is required; sshd combines `User` and `Group` with AND. Names
 * must match `[a-z_][a-z0-9_-]*` (no patterns, negation or commas) and a list
 * must be non-empty and free of duplicates.
 */
export type SshdMatchCriteria = {
  /** Renders `Match Group <names>`: any listed group matches (comma-joined). */
  group?: string | string[]
  /** Renders `Match User <names>`: any listed user matches (comma-joined). */
  user?: string | string[]
}

/** Runtime options of `sshd.match`. */
export type SshdMatchOptions = {
  /**
   * Lockout override: by default (`false`) a change is refused when the
   * criteria match the user of the running Paratix connection, because a later
   * run could then be locked out by the restrictions. Set `true` to accept
   * that deliberately.
   */
  allowConnectionUser?: boolean
  /**
   * Desired drop-in state. Defaults to `"present"`; `"absent"` removes the
   * Paratix-managed drop-in.
   */
  state?: "absent" | "present"
  /**
   * Account that the effective configuration of a `present` drop-in is
   * verified for with `sshd -T -C user=<verifyUser>,…`. It must be a literal
   * user name, and the rules below are validated for `absent` too. Defaults
   * to the first `user` criterion; it is required when only a `group`
   * criterion is given, and it must be listed in `user` when `user` is given.
   * With a `group` criterion the account must belong to one of those groups.
   * A verify user that does not exist yet postpones the effect check in
   * dry-run and makes `apply` of `present` fail.
   */
  verifyUser?: string
}

type SshdYesNo = "no" | "yes"
/** `sshd -T` prints `all` as `yes`, so only the printed forms are canonical. */
type SshdForwarding = "local" | "no" | "remote" | "yes"

/** Directives accepted inside an `sshd.match` block, with their canonical `sshd -T` values. */
export type SshdMatchDirectives = {
  /** `AllowAgentForwarding`: whether ssh-agent forwarding is permitted. */
  AllowAgentForwarding?: SshdYesNo
  /** `AllowStreamLocalForwarding`: whether Unix-domain socket forwarding is permitted. */
  AllowStreamLocalForwarding?: SshdForwarding
  /** `AllowTcpForwarding`: whether TCP forwarding is permitted. */
  AllowTcpForwarding?: SshdForwarding
  /** `AuthenticationMethods`: `any`, or space-separated comma lists of lowercase method names. */
  AuthenticationMethods?: string
  /** `DisableForwarding`: disables all forwarding, X11, agent and stream-local included. */
  DisableForwarding?: SshdYesNo
  /** `ForceCommand`: forced command; non-empty, without leading or trailing whitespace. */
  ForceCommand?: string
  /** `PasswordAuthentication`: whether password authentication is allowed (may weaken). */
  PasswordAuthentication?: SshdYesNo
  /** `PermitTTY`: whether pseudo-terminal allocation is permitted. */
  PermitTTY?: SshdYesNo
  /** `PermitUserRC`: whether `~/.ssh/rc` is executed. */
  PermitUserRC?: SshdYesNo
  /** `PubkeyAuthentication`: whether public key authentication is allowed. */
  PubkeyAuthentication?: SshdYesNo
  /** `X11Forwarding`: whether X11 forwarding is permitted. */
  X11Forwarding?: SshdYesNo
}

/** Normalized, validated `sshd.match` specification produced by {@link buildSshdMatchSpec}. */
export type SshdMatchSpec = {
  /** Whether criteria matching the connection user are accepted. */
  allowConnectionUser: boolean
  /** Complete drop-in text: marker line, `Match` line and indented directives. */
  content: string
  /** Group criteria; empty when only users are given. */
  groups: readonly string[]
  /** First line of the drop-in, which identifies it as Paratix-managed. */
  marker: string
  /** Module name used in results and messages. */
  moduleName: string
  /** Absolute drop-in path below {@link SSHD_MATCH_DROP_IN_DIRECTORY}. */
  path: string
  /** Directives in allowlist order with their canonical `sshd -T` values. */
  settings: Readonly<Record<string, string>>
  /** Desired drop-in state. */
  state: "absent" | "present"
  /** User criteria; empty when only groups are given. */
  users: readonly string[]
  /** Resolved account for `sshd -T -C` verification. */
  verifyUser: string
}

/** Directory sshd loads through the required `Include /etc/ssh/sshd_config.d/*.conf`. */
export const SSHD_MATCH_DROP_IN_DIRECTORY = "/etc/ssh/sshd_config.d"
const NAME_PATTERN = /^[a-z0-9][a-z0-9_\-]{0,63}$/v
const ACCOUNT_PATTERN = /^[a-z_][a-z0-9_\-]*$/v
const CONTROL_PATTERN = /[\p{Cc}\p{Zl}\p{Zp}]/v
const METHOD_NAME = /^[a-z][a-z0-9\-]*$/v
const METHOD_DETAIL = /^[a-z0-9\-]+$/v
const TRUSTED_USER_CA = "ssh.trustedUserCa"
const YES_NO = ["no", "yes"] as const
const FORWARDING = ["local", "no", "remote", "yes"] as const

type DirectiveValidator = (value: string) => string | undefined

function enumValidator(allowed: readonly string[]): DirectiveValidator {
  return (value) =>
    allowed.includes(value) ? undefined : `expected one of ${allowed.join(", ")} (lowercase)`
}

function forwardingValidator(value: string): string | undefined {
  if (value === "all") return 'use "yes"; sshd -T prints "all" as "yes"'
  return enumValidator(FORWARDING)(value)
}

function isAuthenticationMethod(method: string): boolean {
  // A method name with at most one ":detail" suffix, e.g. keyboard-interactive:pam.
  const [base, ...details] = method.split(":")
  return (
    details.length <= 1 && METHOD_NAME.test(base) && details.every((d) => METHOD_DETAIL.test(d))
  )
}

function authenticationMethodsValidator(value: string): string | undefined {
  if (value === "any") return undefined
  const lists = value.split(" ")
  return lists.every((list) => list.split(",").every((method) => isAuthenticationMethod(method)))
    ? undefined
    : 'expected "any" or single-space-separated comma lists of lowercase method names'
}

function forceCommandValidator(value: string): string | undefined {
  if (value.length === 0) return "must not be empty"
  return value.trim() === value ? undefined : "must not have leading or trailing whitespace"
}

// Allowlist in deterministic output order: Match-capable directives whose
// sshd -T representation can be compared exactly.
const DIRECTIVES: ReadonlyMap<string, DirectiveValidator> = new Map([
  ["AllowAgentForwarding", enumValidator(YES_NO)],
  ["AllowStreamLocalForwarding", forwardingValidator],
  ["AllowTcpForwarding", forwardingValidator],
  ["AuthenticationMethods", authenticationMethodsValidator],
  ["DisableForwarding", enumValidator(YES_NO)],
  ["ForceCommand", forceCommandValidator],
  ["PasswordAuthentication", enumValidator(YES_NO)],
  ["PermitTTY", enumValidator(YES_NO)],
  ["PermitUserRC", enumValidator(YES_NO)],
  ["PubkeyAuthentication", enumValidator(YES_NO)],
  ["X11Forwarding", enumValidator(YES_NO)],
])

const MANAGED_DIRECTIVES: ReadonlyMap<string, string> = new Map([
  ["authorizedprincipalsfile", TRUSTED_USER_CA],
  ["hostcertificate", "ssh.hostCertificate"],
  ["port", "sshd.port"],
  ["revokedkeys", TRUSTED_USER_CA],
  ["trustedusercakeys", TRUSTED_USER_CA],
])

function fail(name: string, message: string): never {
  throw new Error(`sshd.match: ${JSON.stringify(name)}: ${message}`)
}

function accountList(name: string, kind: "group" | "user", value: unknown): string[] {
  if (value === undefined) return []
  const list: unknown[] = Array.isArray(value) ? value : [value]
  if (list.length === 0) fail(name, `${kind} criterion must not be an empty list`)
  for (const entry of list) {
    if (typeof entry !== "string" || !ACCOUNT_PATTERN.test(entry)) {
      fail(
        name,
        `${kind} criterion ${JSON.stringify(entry)} must be a literal name matching ` +
          "[a-z_][a-z0-9_-]* (no patterns, negation, commas or empty names)"
      )
    }
  }
  const names = list.filter((entry): entry is string => typeof entry === "string")
  if (new Set(names).size !== names.length) fail(name, `${kind} criterion contains duplicates`)
  return names
}

function parseCriteria(
  name: string,
  criteria: SshdMatchCriteria
): { groups: string[]; users: string[] } {
  const raw: unknown = criteria
  if (typeof raw !== "object" || raw === null) fail(name, "criteria must be an object")
  for (const key of Object.keys(raw)) {
    if (key !== "group" && key !== "user")
      fail(name, `unsupported criterion ${JSON.stringify(key)} (only user and group)`)
  }
  const users = accountList(name, "user", criteria.user)
  const groups = accountList(name, "group", criteria.group)
  if (users.length === 0 && groups.length === 0)
    fail(name, "at least one user or group criterion is required")
  return { groups, users }
}

function validateDirective(name: string, key: string, value: unknown): string {
  const owner = MANAGED_DIRECTIVES.get(key.toLowerCase())
  if (owner !== undefined) fail(name, `directive ${key} is managed by ${owner}; not allowed here`)
  const validator = DIRECTIVES.get(key)
  if (validator === undefined) {
    fail(
      name,
      `unsupported directive ${JSON.stringify(key)}; allowed: ${[...DIRECTIVES.keys()].join(", ")}`
    )
  }
  if (typeof value !== "string") fail(name, `value for ${key} must be a string`)
  if (CONTROL_PATTERN.test(value))
    fail(name, `value for ${key} must not contain control characters or newlines`)
  const problem = validator(value)
  if (problem !== undefined) fail(name, `value ${JSON.stringify(value)} for ${key}: ${problem}`)
  return value
}

function parseDirectives(
  name: string,
  directives: SshdMatchDirectives,
  state: "absent" | "present"
): Record<string, string> {
  const raw: unknown = directives
  if (typeof raw !== "object" || raw === null) fail(name, "directives must be an object")
  const entries: Array<[string, unknown]> = Object.entries(raw)
  const given = entries.filter(([, value]) => value !== undefined)
  const values = new Map(given.map(([key, value]) => [key, validateDirective(name, key, value)]))
  if (state === "present" && values.size === 0) fail(name, "at least one directive is required")
  // Deterministic order follows the allowlist, independent of object key order.
  return Object.fromEntries(
    [...DIRECTIVES.keys()].flatMap((key) => {
      const value = values.get(key)
      return value === undefined ? [] : [[key, value]]
    })
  )
}

function parseState(name: string, state: SshdMatchOptions["state"]): "absent" | "present" {
  const raw: unknown = state
  if (raw === undefined || raw === "present") return "present"
  if (raw === "absent") return "absent"
  return fail(name, `state must be "present" or "absent", got ${JSON.stringify(raw)}`)
}

// Resolves the verify user: explicit, else the first user criterion; mandatory
// for a pure group criterion; must be one of the listed users.
function resolveVerifyUser(
  name: string,
  accounts: { groups: string[]; users: string[] },
  verifyUser: string | undefined
): string {
  const raw: unknown = verifyUser
  if (raw !== undefined && (typeof raw !== "string" || !ACCOUNT_PATTERN.test(raw)))
    fail(name, `verifyUser ${JSON.stringify(raw)} must be a literal user name`)
  if (accounts.groups.length > 0 && verifyUser === undefined)
    fail(name, "verifyUser is required with a group criterion")
  const user = verifyUser ?? accounts.users[0]
  if (accounts.users.length > 0 && !accounts.users.includes(user))
    fail(name, `verifyUser ${user} must be listed in the user criterion`)
  return user
}

function parseOptions(name: string, options: SshdMatchOptions): SshdMatchOptions {
  const raw: unknown = options
  if (typeof raw !== "object" || raw === null) fail(name, "options must be an object")
  for (const key of Object.keys(raw)) {
    if (!["allowConnectionUser", "state", "verifyUser"].includes(key))
      fail(name, `unsupported option ${JSON.stringify(key)}`)
  }
  const allow: unknown = options.allowConnectionUser
  if (allow !== undefined && typeof allow !== "boolean")
    fail(name, "allowConnectionUser must be a boolean")
  return options
}

// Renders the marker line, one `Match` line (User and Group are ANDed by sshd)
// and the indented directives; the text ends with a newline.
function renderDropIn(
  marker: string,
  accounts: { groups: readonly string[]; users: readonly string[] },
  settings: Record<string, string>
): string {
  const criteria = [
    ...(accounts.users.length > 0 ? [`User ${accounts.users.join(",")}`] : []),
    ...(accounts.groups.length > 0 ? [`Group ${accounts.groups.join(",")}`] : []),
  ]
  const lines = Object.entries(settings).map(([key, value]) => `    ${key} ${value}`)
  return [marker, `Match ${criteria.join(" ")}`, ...lines, ""].join("\n")
}

/**
 * Validate every `sshd.match` input at construction time and render the drop-in.
 * @param name - Drop-in name (`/etc/ssh/sshd_config.d/<name>.conf`).
 * @param criteria - Literal user and/or group criteria.
 * @param input - Directives and options.
 * @param input.directives - Allowlisted directives with canonical `sshd -T` values.
 * @param input.options - State, verification user and lockout override.
 * @returns The frozen, normalized module specification.
 * @throws {Error} Prefixed `sshd.match: "<name>"` when the name, criteria,
 *   directives, state or `verifyUser` are invalid.
 */
export function buildSshdMatchSpec(
  name: string,
  criteria: SshdMatchCriteria,
  input: { directives: SshdMatchDirectives; options: SshdMatchOptions }
): SshdMatchSpec {
  const rawName: unknown = name
  if (typeof rawName !== "string" || !NAME_PATTERN.test(rawName))
    fail(String(rawName), "name must match [a-z0-9][a-z0-9_-]{0,63}")
  const options = parseOptions(name, input.options)
  const state = parseState(name, options.state)
  const accounts = parseCriteria(name, criteria)
  const settings = parseDirectives(name, input.directives, state)
  const verifyUser = resolveVerifyUser(name, accounts, options.verifyUser)
  const marker = `# Managed by Paratix sshd.match: ${name}`
  return Object.freeze({
    allowConnectionUser: options.allowConnectionUser ?? false,
    content: renderDropIn(marker, accounts, settings),
    groups: Object.freeze(accounts.groups),
    marker,
    moduleName: `sshd.match: ${name} (${state})`,
    path: `${SSHD_MATCH_DROP_IN_DIRECTORY}/${name}.conf`,
    settings: Object.freeze(settings),
    state,
    users: Object.freeze(accounts.users),
    verifyUser,
  })
}

/**
 * Evaluate the sshd `Match User … Group …` AND semantics for one account.
 * @param spec - Normalized criteria.
 * @param account - Account name and its group names (`null` when unknown).
 * @param account.groups - Group names from `id -Gn`, or `null` when unavailable.
 * @param account.user - Account name.
 * @returns `true`/`false`, or `undefined` when groups are required but unknown.
 */
export function sshdMatchCriteriaMatch(
  spec: Pick<SshdMatchSpec, "groups" | "users">,
  account: { groups: null | readonly string[]; user: string }
): boolean | undefined {
  if (spec.users.length > 0 && !spec.users.includes(account.user)) return false
  if (spec.groups.length === 0) return true
  if (account.groups === null) return undefined
  return account.groups.some((group) => spec.groups.includes(group))
}
