# nzbd 0.6.0 - production bundle

Only what a production install needs: the sources of the two images (app and proxy), the compose stack,
the interactive installer, default configuration and the operator documentation. Nothing for demo,
development, tests or fuzzing.

Start here: **[docs/QUICK_INSTALL.md](docs/QUICK_INSTALL.md)** (`cd deploy && ./install.sh`), or the manual
[docs/INSTALL.md](docs/INSTALL.md). Then [docs/USER_GUIDE.md](docs/USER_GUIDE.md) and
[docs/RUNBOOK.md](docs/RUNBOOK.md) (backups, restore, upgrade, troubleshooting).

Requirements: a host with Docker (Compose v2, BuildKit). No Rust toolchain. The first build needs
internet for base images, crates and the proxy's Go modules; the running stack has no outbound network.
