// Linux user and group names accepted by the account-management modules.
// The leading character must be a lowercase letter or underscore; subsequent
// characters may be lowercase letters, digits, underscores, or hyphens; an
// optional trailing `$` is accepted for samba machine accounts.
const USER_NAME_PATTERN = /^[a-z_][a-z0-9_\-]*\$?$/v

export function assertValidUserName(name: string): void {
  if (!USER_NAME_PATTERN.test(name)) {
    throw new Error(`user name ${JSON.stringify(name)} is invalid`)
  }
}

export function assertValidGroupName(group: string): void {
  if (!USER_NAME_PATTERN.test(group)) {
    throw new Error(`group name ${JSON.stringify(group)} is invalid`)
  }
}
