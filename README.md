# Schipper.Io.Ssh

A minimal, from-scratch SSH-2 server and client (ECDH P-256 key exchange, `aes256-gcm@openssh.com`)
that surfaces each session as a bidirectional byte channel with terminal size/resize, plus a
persistent ECDSA host key (`SshHostKey`) reusable for signing/verification.

Zero dependencies (BCL only) — this is a transport-only library. `SshSession` exposes
`ReadAsync`/`WriteAsync` plus `Columns`/`Rows`/`Resized` and the client-sent `Environment` pairs;
the application adapts it to whatever terminal/rendering abstraction it uses.

- **Server** — `SshServer` with the classic pty/shell path, plus `SshServerOptions` for named
  `subsystem` handlers (no pty) and verified `publickey` user authentication (the authenticated
  username and key fingerprint land on `ConnectionContext`).
- **Client** — `SshClient.ConnectAsync(...)` connects with the same single algorithm set, verifies
  the host key through a caller-supplied verifier, authenticates with `publickey` (falling back to
  `none`), and returns an `SshSession` running a shell or a named subsystem.

## Documentation

Usage of the server, the client, and `SshSession` is in [docs/](docs/README.md).

## Build, test, package

Builds run in the latest .NET 10 SDK container, `mcr.microsoft.com/dotnet/sdk:10.0`. Docker is required. `build.ps1` and `build.sh` both run `container.sh` inside that image. The source is copied into `/tmp` inside the container, so `bin/` and `obj/` stay off the host. A packed package is written to `./dist` and copied to the shared local feed at `../nuget.cache`.

`nuget.config` restores `Schipper.*` from that feed and every other package from nuget.org. `global.json` requests SDK 10.0.100 and rolls forward to the latest .NET 10 SDK in the image.

No flags builds Release. Flags combine. The runtime identifier defaults to `linux-x64` (`RID=win-x64 ./build.sh` or `./build.ps1 -Rid win-x64`).

```bash
./build.sh           # restore + build
./build.sh -t        # unit tests
./build.sh -i        # integration tests, if any
./build.sh -p        # pack into ./dist and ../nuget.cache
./build.sh -r        # run, when the project is an executable
./build.sh -q        # unit tests under dotnet-trace -> ./dist/trace
./build.sh -o        # also write build/test logs to ./dist/raw
./build.sh -t -p     # flags combine
```

```powershell
./build.ps1
./build.ps1 -t -p
```

## Continuous integration

`.github/workflows/build.yml` runs `./build.sh -t -p` on Ubuntu for every push and pull request, using the same SDK container. The packed package is uploaded as the `nuget` workflow artifact.

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
