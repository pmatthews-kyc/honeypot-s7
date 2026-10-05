# Security Policy

## Reporting a vulnerability

If you find a security issue in honeypot-s7 — a bug that could let an attacker
detect it trivially, escape the intended isolation, or use it as a pivot —
please report it privately rather than opening a public issue:

- Open a **GitHub Security Advisory** on this repository
  (Security → Advisories → Report a vulnerability), or
- Contact the maintainer directly (see the repository profile).

Please include the version/commit, how to reproduce, and the impact as you see
it. There is no bounty; this is a volunteer defensive-research project, but
reports are genuinely appreciated and will be credited unless you prefer
otherwise.

## What counts as a vulnerability here

Because this is a honeypot, "vulnerability" has a slightly different meaning
than for normal software:

- **Trivial fingerprinting** — a single probe that cleanly distinguishes this
  from a real S7-300 (a leaked banner, an inconsistent surface, a library tell
  we haven't patched). Known, documented gaps
  (see [`docs/FINGERPRINTING.md`](docs/FINGERPRINTING.md)) are *not*
  vulnerabilities; a new, undocumented one is.
- **Isolation escape** — a path by which a connecting attacker reaches beyond
  the honeypot into the host or the wider network.
- **Information leak to the attacker** — any surface that reveals to a
  connecting client that they are being observed, or exposes the honeypot's
  own machinery (its logs, its process list, its database).

## Responsible use — read before deploying

honeypot-s7 deliberately deceives connecting systems into believing they are a
real industrial controller, and it accepts unauthenticated PLC STOP and
program-transfer commands (which is *correct* S7-300 behavior and part of the
deception). That capability carries responsibility:

- **Deploy only on infrastructure you own or are explicitly authorized to run
  a honeypot on.** Operating a deceptive service can have legal implications
  depending on your jurisdiction and network.
- **Never place it where it could be mistaken for, or interfere with, a real
  control system.** On the wrong network, its unauthenticated STOP behavior is
  a liability, not a feature.
- **Isolate it.** It should sit on an instrumented, monitored segment with no
  path to production OT or IT. Treat every connection to it as hostile.
- **You are responsible for the data you capture.** Attacker traffic may
  contain sensitive or illegal material; store, handle, and dispose of it
  according to your legal and organizational obligations.

This software is provided under the GPL with **no warranty**. You assume all
risk of deployment.

## Supported versions

This is an early-stage project. Security fixes are applied to the latest
`main`; there is no long-term-support branch. Run a recent checkout.
