# Sluice

A desktop intercepting proxy for testing web applications, written in Rust with a Tauri and React interface.

"Sluice" is a working name.

## Responsible use

Only test systems you own or have explicit written permission to test. Intercepting or attacking other people's systems without permission is illegal in most places.

Sluice's fuzzer refuses any target that is not listed in the project's scope, and shows the total number of requests before it sends anything.

The certificate authority Sluice creates can impersonate any website to whichever browser trusts it. Install it only in a browser profile reserved for testing, and never share `sluice-ca.key`.

## Features

- **Proxy:** HTTP/1.1, HTTPS interception with a certificate authority generated per install, and WebSocket capture.
- **History:** every request and response stored as exact bytes in a SQLite project file, with filtering and raw search.
- **Intercept:** pause requests or responses, edit them, then forward or drop them.
- **Repeater:** edit and resend requests in saved tabs.
- **Fuzzer:** four attack types, with payloads from lists, number ranges or files. Concurrency and delay are configurable, and runs can be paused or stopped.
- **Findings:** passive checks on recorded in-scope traffic. Scanning never sends a request.

## Limits in this version

- No HTTP/2. Clients are offered HTTP/1.1 only, so sites that require HTTP/2 will not work.
- Upstream TLS 1.0 and 1.1 are not supported.
- WebSocket frames are recorded but cannot be edited.
- Raw history search does not look inside compressed bodies.
- There is no active scanner and no extension system.

## Setup

You need Rust (stable), Node.js, the Tauri CLI, and on Linux the WebKitGTK 4.1 and GTK 3 development packages.

```bash
cargo install tauri-cli --version "^2" --locked
```

```bash
npm --prefix ui install
```

Run in development:

```bash
cargo tauri dev
```

Build a Debian package, written to `target/release/bundle/deb/`:

```bash
cargo tauri build
```

## First run

1. If the listener cannot use `127.0.0.1:8080`, choose another port in **Settings**.
2. Add the hosts you are authorized to test under **Scope**.
3. Click **Open Chrome** or **Open Firefox** at the top of the window.

These buttons appear when the browser is installed. Each opens a separate profile stored in Sluice's data folder, already set up to use the proxy and trust its certificate. Your own browser profiles and the system certificate store are not changed.

To use another browser, save the certificate from **Settings**, import it into a profile reserved for testing, and set that browser's HTTP and HTTPS proxy to the listener address.

## Layout

| Path | Contents |
| --- | --- |
| `crates/core` | Proxy, storage, repeater, fuzzer and scanner, with no Tauri dependency |
| `src-tauri` | Commands and event bridge between the engine and the window |
| `ui` | React interface |

## Tests

```bash
cargo test --workspace
```

To also test against the installed Chrome and Firefox:

```bash
cargo test -p sluice-core --test browsers -- --ignored --test-threads=1
```

To view the interface with sample data in a normal browser, run `npm --prefix ui run dev` and open `http://localhost:5173`.
