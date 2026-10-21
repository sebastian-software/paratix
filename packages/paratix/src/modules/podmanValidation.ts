import { posix } from "node:path"

import type { PodmanConfiguration, PodmanLoginOptions, PodmanOptions } from "./podmanTypes.js"

import { ENVIRONMENT_FORBIDDEN_KEYS } from "../environment.js"
import {
  PODMAN_AUTH_FILE,
  PODMAN_HELPER_IMAGE,
  PODMAN_TOKEN_LIMIT,
  PODMAN_USERNAME_LIMIT,
  PodmanError,
} from "./podmanTypes.js"

const DNS_HOST_LIMIT = 253
const DNS_LABEL_LIMIT = 63
const PORT_LIMIT = 65_535
const IPV4_PARTS = 4
const IPV4_OCTET_LIMIT = 255
const PATH_LIMIT = 512

function validHost(host: string): boolean {
  return (
    host.length <= DNS_HOST_LIMIT &&
    host
      .split(".")
      .every(
        (part) =>
          part.length > 0 &&
          part.length <= DNS_LABEL_LIMIT &&
          /^[a-z0-9\-]+$/v.test(part) &&
          !part.startsWith("-") &&
          !part.endsWith("-")
      )
  )
}
function validatePort(port: string | undefined): void {
  if (
    port !== undefined &&
    (!/^\d+$/v.test(port) || Number(port) < 1 || Number(port) > PORT_LIMIT)
  ) {
    throw new PodmanError("invalid registry port")
  }
}
export function normalizeRegistry(registry: unknown): string {
  if (typeof registry !== "string") throw new PodmanError("invalid registry")
  const parts = registry.toLowerCase().split(":")
  let host = parts[0]
  if (parts.length > 2 || !validHost(host)) throw new PodmanError("invalid registry host")
  validatePort(parts[1])
  if (
    /^[\d.]+$/v.test(host) &&
    (host.split(".").length !== IPV4_PARTS ||
      host.split(".").some((part) => Number(part) > IPV4_OCTET_LIMIT))
  ) {
    throw new PodmanError("invalid registry address")
  }
  if (["index.docker.io", "registry-1.docker.io"].includes(host)) host = "docker.io"
  return host + (parts.length === 1 ? "" : `:${String(Number(parts[1]))}`)
}
export function validateUsername(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value) > PODMAN_USERNAME_LIMIT ||
    /[:\s\p{Cc}\p{Cs}]/v.test(value)
  ) {
    throw new PodmanError("invalid username")
  }
}
export function validateToken(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value) > PODMAN_TOKEN_LIMIT ||
    value.trim() !== value ||
    /[\p{Cc}\p{Cs}\p{Zl}\p{Zp}]/v.test(value)
  ) {
    throw new PodmanError("invalid token")
  }
}
function validateBinding(value: unknown): void {
  if (
    typeof value !== "string" ||
    ENVIRONMENT_FORBIDDEN_KEYS.has(value) ||
    !value.split(".").every((part) => /^[A-Za-z_]\w*$/v.test(part))
  ) {
    throw new PodmanError("invalid environment binding")
  }
}
const BROAD_DIRECTORIES = new Set([
  "/",
  "/etc",
  "/home",
  "/opt",
  "/root",
  "/root/.config",
  "/run",
  "/srv",
  "/tmp",
  "/usr",
  "/var",
  "/var/lib",
  "/var/run",
])
function validateDedicatedParent(value: string): void {
  const parent = posix.dirname(value)
  if (BROAD_DIRECTORIES.has(parent) || /^\/home\/[^\/]+$/v.test(parent)) {
    throw new PodmanError("file requires a dedicated parent directory")
  }
}
export function validatePodmanPath(value: unknown, mounted = true): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length > PATH_LIMIT ||
    !/^\/[\w.\/\-]+$/v.test(value) ||
    value !== posix.normalize(value) ||
    value.endsWith("/")
  ) {
    throw new PodmanError("invalid file path")
  }
  if (value.split("/").some((part) => part === "." || part === ".."))
    throw new PodmanError("invalid file path")
  if (mounted) validateDedicatedParent(value)
}
function validateImage(image: unknown): asserts image is string {
  if (typeof image !== "string" || image.length > PATH_LIMIT)
    throw new PodmanError("invalid helperImage")
  const imageParts = image.split("@sha256:")
  const [name, digest] = imageParts
  const [host, ...path] = name.split("/")
  if (
    imageParts.length !== 2 ||
    !/^[a-f\d]{64}$/v.test(digest) ||
    path.length === 0 ||
    (!host.includes(".") && host.split(":")[0] !== "localhost")
  ) {
    throw new PodmanError("helperImage must be fully qualified and pinned by SHA-256 digest")
  }
  normalizeRegistry(host)
  if (!path.every((part) => /^[a-z\d][a-z\d._:\-]*$/v.test(part)))
    throw new PodmanError("invalid helperImage repository")
}
function validateFileSource(input: Record<string, unknown>, authFile: string): void {
  if (
    input.passwordFileLocation !== undefined &&
    input.passwordFileLocation !== "target" &&
    input.passwordFileLocation !== "controller"
  )
    throw new PodmanError("invalid passwordFileLocation")
  validatePodmanPath(input.passwordFile, input.passwordFileLocation === "target")
  if (input.passwordFileLocation === "target" && input.passwordFile === authFile)
    throw new PodmanError("auth and token files must differ")
}
function validateSources(input: Record<string, unknown>, authFile: string): void {
  if (
    (input.username !== undefined) === (input.usernameEnv !== undefined) ||
    (input.passwordFile !== undefined) === (input.passwordEnv !== undefined)
  )
    throw new PodmanError("exactly one source per credential is required")
  if (input.username === undefined) validateBinding(input.usernameEnv)
  else validateUsername(input.username)
  if (input.passwordEnv === undefined) validateFileSource(input, authFile)
  else {
    validateBinding(input.passwordEnv)
    if (input.passwordFileLocation !== undefined)
      throw new PodmanError("passwordFileLocation requires passwordFile")
  }
  if ("password" in input) throw new PodmanError("plaintext password options are unsupported")
}
export function configuration(
  registry: string,
  options: PodmanOptions,
  source?: PodmanLoginOptions
): PodmanConfiguration {
  const authFile = options.authFile ?? PODMAN_AUTH_FILE
  const helperImage = options.helperImage ?? PODMAN_HELPER_IMAGE
  validatePodmanPath(authFile)
  validateImage(helperImage)
  if (source) validateSources(source, authFile)
  return {
    authFile,
    helperImage,
    operation: source ? "login" : "logout",
    registry: normalizeRegistry(registry),
    source,
  }
}
