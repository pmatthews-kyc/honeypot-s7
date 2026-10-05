# Contributing

Contributions are welcome — bug fixes, new deception layers, better
documentation, additional protocol coverage. A few things specific to this
project will make your contribution easier to accept.

## The core principle: build, then actually run it

Nearly every subtle bug in this project's history was caught by *running* the
code — against the test suite, against real scanning tools, against a live
deployment — not by inspection. Wrong SNMP type tags, wrong SZL byte offsets,
an empty-versus-absent HTTP header, the entire snap7 memory-model
misunderstanding: none were visible by reading the code.

So: **new behavior needs a test that exercises it against real logic**, not a
mock that asserts your assumptions back at you. If you're adding a deception
layer, ideally validate it against the tool it's meant to defeat (`nmap`,
`plcscan`, `snmpwalk`, a real S7 client) and note the result in the PR.

## Running the tests

```bash
cd tests
# Standalone — no extra dependencies:
for t in test_*.py; do python3 "$t"; done
# Or with pytest if you have it (pip install pytest):
python3 -m pytest
```

All tests must pass before a PR is merged. They import the modules from `src/`
via `conftest.py`, and use `config.yaml.example` for fixtures.

## Style

- **Match the surrounding code.** It's plain, explicit Python — no clever
  metaprogramming, clear names, comments that explain *why* not *what*.
- **No hardcoded state paths.** Every runtime file location resolves through
  `paths.py` from `config.yaml`. If you need a new state file, add it there —
  don't hardcode `/var/lib/...` in a module. (`tests/test_paths.py` guards
  this.)
- **Nothing attacker-visible may reveal the machinery.** Anything written to
  the diagnostic buffer (readable over S7comm and the web portal) is filtered
  against a forbidden-term list in `diag_log.py`. Don't work around it —
  operator/debug detail belongs in the service journal, not the buffer.
- **Keep the surfaces consistent.** Identity, SNMP, and the web portal all draw
  from one config. A change that makes one surface disagree with another is a
  fingerprint, not a feature.

## What's especially welcome

The known gaps in [`docs/FINGERPRINTING.md`](docs/FINGERPRINTING.md) are the
highest-value targets:

- **TCP options *ordering* in the SYN-ACK** — the strongest remaining passive
  `p0f`/`nmap -O` signal, needing a raw-socket handshake rebuild.
- **Real MC7 bytecode** for block read-back.
- **Broader SZL coverage** validated against real hardware captures.

## Legal / scope

By contributing you agree your contribution is licensed under the project's
GPL-3.0. Please don't contribute anything derived from proprietary Siemens
firmware, real captured device identities, or code you don't have the right to
relicense. Device-*class* emulation from public documentation is the line this
project stays on — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
