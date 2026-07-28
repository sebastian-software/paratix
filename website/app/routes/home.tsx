import type { ReactElement } from "react"

import {
  ArrowDown,
  ArrowRight,
  Check,
  CircleCheckBig,
  Clipboard,
  CodeXml,
  Eye,
  KeyRound,
  Layers,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  SquareTerminal,
  X,
} from "lucide-react"
import { useRef, useState } from "react"

import type { Route } from "./+types/home"

const scaffoldCommand = "pnpm create paratix my-server"
const COPY_STATUS_DURATION_MS = 1800

const playbook = `import { server } from "paratix"
import { hostname, package as pkg, service } from "paratix/modules"

export default server({
  name: "web-01",
  host: "10.0.0.1",
  ssh: { user: "root", ports: [22] },
  run: [
    hostname.set("web-01"),
    pkg.installed("nginx", "curl"),
    service.enabled("nginx"),
    service.running("nginx"),
  ],
})`

export const meta: Route.MetaFunction = () => {
  const title = "Paratix | TypeScript server automation over SSH"
  const description =
    "Define a Linux server in TypeScript, preview the exact changes, and apply only what is needed over SSH with Paratix."

  return [
    { title },
    { content: description, name: "description" },
    { content: "website", property: "og:type" },
    { content: title, property: "og:title" },
    { content: description, property: "og:description" },
    { content: "/paratix-og.png", property: "og:image" },
    { content: "Paratix TypeScript playbook for an nginx server", property: "og:image:alt" },
    { content: "summary_large_image", name: "twitter:card" },
    { content: title, name: "twitter:title" },
    { content: description, name: "twitter:description" },
    { content: "/paratix-og.png", name: "twitter:image" },
  ]
}

function CopyCommand(): ReactElement {
  const [status, setStatus] = useState<"copied" | "error" | "idle">("idle")
  const commandInput = useRef<HTMLInputElement>(null)

  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(scaffoldCommand)
      setStatus("copied")
      globalThis.setTimeout(() => {
        setStatus("idle")
      }, COPY_STATUS_DURATION_MS)
    } catch {
      setStatus("error")
      commandInput.current?.focus()
      commandInput.current?.select()
    }
  }

  let announcement = ""
  if (status === "copied") announcement = "Scaffold command copied"
  if (status === "error") {
    announcement = "Copy failed. The command is selected; copy it with your keyboard."
  }

  return (
    <div className="command-line">
      <input
        aria-label="Scaffold command"
        onFocus={(event) => {
          event.currentTarget.select()
        }}
        readOnly
        ref={commandInput}
        value={scaffoldCommand}
      />
      <button
        aria-label="Copy scaffold command"
        onClick={() => {
          void copy()
        }}
        title="Copy scaffold command"
        type="button"
      >
        {status === "copied" ? <Check aria-hidden="true" /> : <Clipboard aria-hidden="true" />}
        <span>{status === "copied" ? "Copied" : "Copy"}</span>
      </button>
      <span aria-live="polite" className="sr-only">
        {announcement}
      </span>
      {status === "error" ? (
        <span className="copy-error">Copy failed. Press Ctrl+C or Cmd+C.</span>
      ) : null}
    </div>
  )
}

const pains = [
  {
    number: "01",
    text: "Configuration grows, but types and editor refactors do not grow with it.",
    title: "YAML drifts from intent",
  },
  {
    number: "02",
    text: "A command that worked once is not proof that rerunning it is safe.",
    title: "Shell scripts forget state",
  },
  {
    number: "03",
    text: "An unsafe sshd or firewall change can lock you out mid-run. Reconnect-aware execution keeps that risk explicit.",
    title: "Hardening can close the door",
  },
]

const features = [
  {
    icon: CodeXml,
    text: "Imports, conditions, composition, types, and the editor tooling you already use.",
    title: "Real TypeScript",
  },
  {
    icon: RefreshCw,
    text: "Each module checks the remote state first and applies only necessary changes.",
    title: "Idempotent modules",
  },
  {
    icon: Eye,
    text: "Preview the run, then request unified diffs from modules that support them.",
    title: "Dry-run and diff",
  },
  {
    icon: KeyRound,
    text: "Reconnect across SSH port changes and reboots with bounded retry windows.",
    title: "SSH-aware execution",
  },
  {
    icon: Layers,
    text: "Group work and defer reloads until a surrounding scope actually changed.",
    title: "Recipes and signals",
  },
  {
    icon: ShieldCheck,
    text: "Separate first-run hardening from normal operation and keep host-key checks strict.",
    title: "Explicit bootstrap",
  },
]

export default function Home(): ReactElement {
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="site-header">
        <a className="wordmark" href="#top">
          <span aria-hidden="true">p</span>paratix
        </a>
        <nav aria-label="Primary navigation">
          <a href="#workflow">Workflow</a>
          <a href="#compare">Compare</a>
          <a href="#status">Status</a>
        </nav>
      </header>

      <main id="main">
        <section aria-labelledby="hero-title" className="hero" id="top">
          <div className="hero-copy">
            <p className="eyebrow">
              <span>Private preview</span> Built for Linux servers over SSH
            </p>
            <h1 id="hero-title">
              Your server,
              <br />
              defined in TypeScript.
            </h1>
            <p className="hero-summary">
              Paratix turns a typed playbook into a careful server run: inspect state, show what
              would change, then apply only what is needed. No YAML and no server-side agent.
            </p>
            <CopyCommand />
            <div className="hero-actions">
              <a href="#workflow">Read the 5-minute guide</a>
              <a href="#status">GitHub · planned</a>
            </div>
            <p className="availability">
              The project is preparing for open-source release. The command shows the intended
              workflow and is not yet publicly installable.
            </p>
          </div>

          <figure className="hero-code" id="og-artwork">
            <figcaption>
              <span className="traffic">
                <i />
                <i />
                <i />
              </span>
              <span>server.ts</span>
              <span>TypeScript</span>
            </figcaption>
            <pre>
              <code>{playbook}</code>
            </pre>
          </figure>

          <a className="section-cue" href="#friction">
            <span>Why Paratix</span>
            <ArrowDown aria-hidden="true" />
          </a>
        </section>

        <section aria-labelledby="friction-title" className="friction" id="friction">
          <div className="section-heading">
            <p className="kicker">The friction</p>
            <h2 id="friction-title">Server automation should feel like engineering.</h2>
          </div>
          <div className="pain-list">
            {pains.map((pain) => (
              <article key={pain.number}>
                <span>{pain.number}</span>
                <h3>{pain.title}</h3>
                <p>{pain.text}</p>
              </article>
            ))}
          </div>
        </section>

        <section aria-labelledby="workflow-title" className="workflow" id="workflow">
          <div className="section-heading">
            <p className="kicker">How it works</p>
            <h2 id="workflow-title">Scaffold. Inspect. Apply.</h2>
            <p>
              One local project, one direct SSH connection, and no resident agent on the server.
            </p>
          </div>
          <div className="workflow-grid">
            <ol className="steps">
              <li>
                <span>1</span>
                <div>
                  <h3>Scaffold the project</h3>
                  <code>pnpm create paratix my-server</code>
                </div>
              </li>
              <li className="active">
                <span>2</span>
                <div>
                  <h3>Preview the run</h3>
                  <code>pnpm apply:dry -- --diff</code>
                </div>
              </li>
              <li>
                <span>3</span>
                <div>
                  <h3>Apply the state</h3>
                  <code>pnpm apply</code>
                </div>
              </li>
            </ol>
            <div aria-label="Example Paratix dry-run output" className="terminal">
              <div className="terminal-bar">
                <SquareTerminal aria-hidden="true" />
                <span>paratix apply · dry run</span>
                <span className="terminal-ok">0 errors</span>
              </div>
              <pre>
                <code>
                  <span className="muted">◆ web-01 · 10.0.0.1</span>
                  {"\n"}
                  <span className="good">✓ hostname · unchanged</span>
                  {"\n"}
                  <span className="change">● package nginx · would change</span>
                  {"\n"}
                  {"\n"}
                  <span className="diff-old">- nginx is not installed</span>
                  {"\n"}
                  <span className="diff-new">+ nginx 1.24.0 will be installed</span>
                  {"\n"}
                  {"\n"}
                  <span className="change">● service nginx · would change</span>
                  {"\n"}
                  <span className="diff-new">+ enabled and running</span>
                  {"\n"}
                  {"\n"}
                  <span className="muted">Summary 2 changed · 1 unchanged</span>
                </code>
              </pre>
            </div>
          </div>
        </section>

        <section aria-labelledby="features-title" className="features">
          <div className="section-heading">
            <p className="kicker">What you get</p>
            <h2 id="features-title">A compact tool with practical depth.</h2>
            <p>
              Twenty-eight exported module groups cover common server resources, from packages and
              files to systemd, firewalls, containers, and users.
            </p>
          </div>
          <div className="feature-grid">
            {features.map(({ icon: Icon, text, title }) => (
              <article key={title}>
                <Icon aria-hidden="true" />
                <h3>{title}</h3>
                <p>{text}</p>
              </article>
            ))}
          </div>
        </section>

        <section aria-labelledby="compare-title" className="comparison" id="compare">
          <div className="section-heading">
            <p className="kicker">Choose deliberately</p>
            <h2 id="compare-title">Use the smallest tool that fits.</h2>
          </div>
          <div aria-label="Scrollable tool comparison" className="comparison-wrap" tabIndex={0}>
            <table>
              <thead>
                <tr>
                  <th scope="col">Need</th>
                  <th className="chosen" scope="col">
                    Paratix
                  </th>
                  <th scope="col">Ansible</th>
                  <th scope="col">bash</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">Authoring model</th>
                  <td className="chosen">Typed code</td>
                  <td>YAML + plugins</td>
                  <td>Imperative script</td>
                </tr>
                <tr>
                  <th scope="row">Remote footprint</th>
                  <td className="chosen">SSH only</td>
                  <td>SSH + Python commonly</td>
                  <td>SSH + shell</td>
                </tr>
                <tr>
                  <th scope="row">State awareness</th>
                  <td className="chosen">
                    <CircleCheckBig /> Built in
                  </td>
                  <td>
                    <CircleCheckBig /> Built in
                  </td>
                  <td>
                    <X /> You build it
                  </td>
                </tr>
                <tr>
                  <th scope="row">Best fit</th>
                  <td className="chosen">Small TypeScript teams</td>
                  <td>Large, diverse fleets</td>
                  <td>Short one-off tasks</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="not-for">
            <ServerCog aria-hidden="true" />
            <div>
              <h3>When not to use Paratix</h3>
              <p>
                Choose a broader platform for dynamic cloud provisioning, a central inventory,
                event-driven orchestration, or a large heterogeneous fleet. Choose bash when the
                task is truly disposable.
              </p>
            </div>
          </div>
        </section>

        <section aria-labelledby="trust-title" className="trust">
          <div>
            <p className="kicker">Trust comes from inspection</p>
            <h2 id="trust-title">No hidden control plane.</h2>
          </div>
          <ul>
            <li>
              <CircleCheckBig /> Open TypeScript playbooks stay in your repository.
            </li>
            <li>
              <CircleCheckBig /> Dry-runs expose intended work before mutation.
            </li>
            <li>
              <CircleCheckBig /> Explicit host-key and first-run workflows support careful
              bootstrapping.
            </li>
            <li>
              <CircleCheckBig /> MIT licensing is prepared for the public release.
            </li>
            <li>
              <CircleCheckBig /> GitHub and npm publication are planned, but not public yet.
            </li>
            <li>
              <CircleCheckBig /> Package changelogs record releases and security hardening work.
            </li>
            <li>
              <CircleCheckBig /> Scoped secrets are redacted from command output and errors.
            </li>
          </ul>
        </section>

        <section aria-labelledby="cta-title" className="final-cta" id="status">
          <p className="kicker">Opening soon</p>
          <h2 id="cta-title">The code is being prepared for release.</h2>
          <p>
            Paratix is not publicly available yet. This repository-owned site is ready for the
            moment the project, package, and documentation go live.
          </p>
          <CopyCommand />
          <a className="back-to-playbook" href="#top">
            Explore the playbook <ArrowRight aria-hidden="true" />
          </a>
        </section>
      </main>

      <footer>
        <a className="wordmark" href="#top">
          <span>p</span>paratix
        </a>
        <p>TypeScript server automation. Preparing for open source.</p>
        <p>© 2026 Sebastian Software GmbH</p>
      </footer>
    </>
  )
}
