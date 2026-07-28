import type { Config } from "@react-router/dev/config"

// No `future` block: the v7 upgrade guide lists five v8_ opt-ins, but those
// are meant to be adopted while still on v7. On v8 itself the flags are gone —
// middleware, pass-through requests, trailing-slash-aware data requests and the
// Vite Environment API are always on, and splitRouteModules moved to a
// top-level field that already defaults to true. Setting any of them is a hard
// config error here.
export default {
  prerender: ["/"],
  ssr: true,
} satisfies Config
