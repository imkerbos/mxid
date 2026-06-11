<!-- One-line PR title above (semantic-commit style preferred: feat:, fix:, refactor:, docs:, chore:) -->

## Summary

<!-- 1-3 bullets. What changes and why. Link issues with `Closes #N`. -->

-

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (API, DB schema, config)
- [ ] Refactor (no behavior change)
- [ ] Documentation only
- [ ] Build / CI / tooling

## How was it tested

<!-- Be specific. "Ran make verify" alone is not enough. -->

- [ ] `make verify` (lint + typecheck + tests + smoke)
- [ ] Manual: …
- [ ] Integration: …

## Checklist

- [ ] PR title follows semantic-commit format.
- [ ] Migrations added for any schema change, with matching `.up.sql` + `.down.sql`.
- [ ] Settings layer touched? Updated default value + UI page + i18n.
- [ ] Protocol behavior touched? Updated relevant doc under `web/apps/console/src/pages/docs/guides.ts`.
- [ ] i18n keys added for any new user-facing string (zh-CN + en-US).
- [ ] No `console.log` / debug `fmt.Println` left in source.
- [ ] CHANGELOG.md updated.

## Screenshots / curl traces

<!-- Required for UI changes and protocol behavior changes. -->
