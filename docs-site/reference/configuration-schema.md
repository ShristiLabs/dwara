# Configuration schema

The exhaustive, machine-readable JSON Schema for the gateway config is
generated straight from the code and committed at
[`config-reference.json`](https://github.com/shristilabs/dwara/blob/main/config-reference.json)
in the repository root. It is regenerated with:

```sh
dwara-cli schema > config-reference.json
```

CI fails a pull request whose committed schema drifts from what the
current code generates, so this file is always in sync with the
config the running binary actually accepts — treat it as the source of
truth for field names, types, and constraints, and this site's
[Configuration guide](../guide/configuration) as the narrative
explanation of the concepts behind it.

If you're building editor tooling, linters, or config generators
against dwara, point them at `config-reference.json` for the given
release (or the `unstable` build's copy, for the in-development
schema) rather than re-deriving the shape by hand.
