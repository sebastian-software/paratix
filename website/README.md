# Paratix website

Private, repository-owned preparation for the Paratix product site. It does not imply that the project, package, domain, or hosting is publicly available.

```bash
pnpm --filter @sebastian-gmbh/paratix-website dev
pnpm --filter @sebastian-gmbh/paratix-website build
pnpm --filter @sebastian-gmbh/paratix-website preview
pnpm --filter @sebastian-gmbh/paratix-website test
```

React Router prerenders `/` during the production build. The website test inspects the emitted `build/client/index.html` and fails unless it contains the page content, metadata, and relative social image references.
