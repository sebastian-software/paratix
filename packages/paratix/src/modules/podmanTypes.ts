// Podman 4.9.3 reads password stdin with a 64 KiB scanner buffer.
export const PODMAN_TOKEN_LIMIT = 65_535
export const PODMAN_USERNAME_LIMIT = 65_536
export const PODMAN_PROTOCOL_BASE_CODE = 80

export const PODMAN_HELPER_IMAGE =
  "docker.io/library/python@sha256:db3231d3fce4c59182f8364dbec08b8bad4fdfca673dfb226f3c9e77b6b48cd2"
export const PODMAN_AUTH_FILE = "/root/.config/containers/auth.json"

export type PodmanOptions = {
  /** Persistent target auth JSON; defaults to /root/.config/containers/auth.json. */
  authFile?: string
  /** Trusted digest-pinned image, already present in the target rootful Podman store. */
  helperImage?: string
}
type UsernameSource =
  { username: string; usernameEnv?: never } | { username?: never; usernameEnv: string }
type PasswordSource =
  | { passwordEnv: string; passwordFile?: never; passwordFileLocation?: never }
  | {
      passwordEnv?: never
      passwordFile: string
      passwordFileLocation?: "controller" | "target"
    }
/**
 * Choose one username source and one token source independently.
 * Environment names refer to preceding resolver bindings, never process.env.
 * Token files require exactly 0400; their default location is the controller.
 */
export type PodmanLoginOptions = { registry: string } & PasswordSource &
  PodmanOptions &
  UsernameSource
export type PodmanConfiguration = {
  authFile: string
  helperImage: string
  operation: "login" | "logout"
  registry: string
  source?: PodmanLoginOptions
}
export type PodmanCredentials = { password?: string; username?: string }

/** This boundary deliberately discards provider, filesystem and command causes. */
export class PodmanError extends Error {
  public constructor(message: string) {
    super(`podman: ${message}`)
    this.name = "PodmanError"
  }
}
