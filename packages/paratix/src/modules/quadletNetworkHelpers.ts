import {
  compactQuadletLines,
  CONTAINERS_SYSTEMD_DIRECTORY,
  maybeRenderQuadletBool,
  maybeRenderQuadletLine,
  renderQuadletKeyValue,
  renderQuadletLine,
  renderQuadletRepeated,
  renderQuadletSection,
} from "./quadletHelpers.js"

export type QuadletNetworkOptions = {
  description?: string
  disableDns?: boolean
  dns?: string[]
  driver?: string
  gateway?: string
  internal?: boolean
  ipamDriver?: string
  ipRange?: string
  ipv6?: boolean
  label?: Record<string, string>
  name: string
  options?: Record<string, string>
  podmanArgs?: string[]
  subnet?: string
}

export function getQuadletNetworkFilePath(name: string): string {
  return `${CONTAINERS_SYSTEMD_DIRECTORY}/${name}.network`
}

/**
 * Build the `[Network]` section lines for a Quadlet `.network` unit in a
 * stable, deterministic order. Every value flows through the same
 * control-character-rejecting render helpers as the container path, and
 * `Label=`/`Options=` are emitted as repeated `key=value` lines sorted by key
 * (matching `podman-network.unit(5)`).
 *
 * @param options - The network definition.
 * @returns The rendered `[Network]` lines (without the section header).
 */
export function buildQuadletNetworkUnitLines(options: QuadletNetworkOptions): string[] {
  return compactQuadletLines([
    renderQuadletLine("NetworkName", options.name),
    maybeRenderQuadletLine("Driver", options.driver),
    maybeRenderQuadletLine("IPAMDriver", options.ipamDriver),
    maybeRenderQuadletBool("Internal", options.internal),
    maybeRenderQuadletBool("IPv6", options.ipv6),
    maybeRenderQuadletBool("DisableDNS", options.disableDns),
    maybeRenderQuadletLine("Subnet", options.subnet),
    maybeRenderQuadletLine("Gateway", options.gateway),
    maybeRenderQuadletLine("IPRange", options.ipRange),
    ...renderQuadletRepeated("DNS", options.dns ?? []),
    ...renderQuadletKeyValue("Options", options.options ?? {}),
    ...renderQuadletKeyValue("Label", options.label ?? {}),
    ...renderQuadletRepeated("PodmanArgs", options.podmanArgs ?? []),
  ])
}

/**
 * Render the complete Quadlet `.network` unit text.
 *
 * A `.network` unit needs neither the `network-online` ordering nor the
 * `[Install]` target of a `.container`: Podman creates the network lazily when
 * a referencing container starts, and the generated container service depends
 * on this unit automatically. Only a `[Unit]` description (for friendly
 * `systemctl` output) and the `[Network]` section are emitted.
 *
 * @param options - The network definition.
 * @returns The rendered unit file content.
 */
export function generateNetworkQuadlet(options: QuadletNetworkOptions): string {
  const sections = [
    renderQuadletSection("Unit", [
      renderQuadletLine("Description", options.description ?? `Podman network: ${options.name}`),
    ]),
    renderQuadletSection("Network", buildQuadletNetworkUnitLines(options)),
  ]
  return sections.join("\n").trimEnd()
}
