# Changesets

Cada cambio que deba publicarse lleva un changeset: un archivo que indica el tipo de
versión (patch / minor / major) y una descripción para el CHANGELOG.

```bash
pnpm changeset          # describe el cambio
pnpm version-packages   # aplica los changesets: versión + CHANGELOG
pnpm release            # compila y publica en npm (lo hace el workflow de release)
```
