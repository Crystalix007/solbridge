# solbridge

TCP-to-iDRAC Serial-over-LAN bridge. SSHes into iDRAC v7, opens `console com2`, and exposes the serial console on a local TCP port for multiple concurrent clients.

## Build

```bash
go build -o solbridge .
```

## Usage

```bash
./solbridge -host idrac.local -i ~/.ssh/idrac localhost:9119
```

Then connect with any TCP client:

```bash
nc localhost 9119
```

Multiple clients share the same SOL session — output is broadcast, input is serialized. Survives SSH drops with exponential-backoff reconnection.

### Flags

| Flag | Required | Description |
|------|----------|-------------|
| `-host` | yes | iDRAC SSH host (resolved from `~/.ssh/config`) |
| `-i` | yes | SSH identity file |
| `-u` | `root` | SSH user |

The listen address is a positional argument (e.g. `localhost:9119` or `:2300`).
