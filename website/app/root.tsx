import type { ReactElement, ReactNode } from "react"

import { Links, Meta, Outlet, Scripts, ScrollRestoration } from "react-router"

import type { Route } from "./+types/root"

import "./styles.css"

export const links: Route.LinksFunction = () => [
  { href: "/icon.svg", rel: "icon", type: "image/svg+xml" },
]

export function Layout({ children }: { children: ReactNode }): ReactElement {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta content="width=device-width, initial-scale=1" name="viewport" />
        <Meta />
        <Links />
      </head>
      <body>
        {children}
        <ScrollRestoration />
        <Scripts />
      </body>
    </html>
  )
}

export default function App(): ReactElement {
  return <Outlet />
}
