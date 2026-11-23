# users-chat browser cryptography integrity

This repository holds the version history of the three static files the `users-chat` Additive serves
for its end-to-end encryption in the browser, with their correlating hashes:

| Artifact                    | Served at                                                   | Meaning                                         |
|-----------------------------|-------------------------------------------------------------|-------------------------------------------------|
| `users-chat_crypto`         | `/users-chat/static/js/chat.js`                             | All browser cryptography of the chat            |
| `users-chat_vodozemac`      | `/users-chat/static/vendor/vodozemac/<v>/vodozemac_bg.js`   | The JavaScript bindings of vodozemac            |
| `users-chat_vodozemac_wasm` | `/users-chat/static/vendor/vodozemac/<v>/vodozemac_bg.wasm` | The vodozemac WebAssembly module `chat.js` pins |

## Contents

| Path                                  | Meaning                                                                                                                |
|---------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `crypto/v<N>.js`                      | The published source of every version of `static/js/chat.js`.                                                          |
| `vodozemac/<x.y.z>/vodozemac_bg.js`   | The bindings of every vendored vodozemac release, unmodified from `@towns-protocol/vodozemac`.                          |
| `vodozemac/<x.y.z>/vodozemac_bg.wasm` | The WebAssembly module of the same release, unmodified.                                                                |
| `generate.py`                         | Computes the SHA-256 of every version and writes `manifest.json` (and `<folder>/hashes/`).                             |
| `manifest.json`                       | The public reference, format 2: per artifact one entry per version (`version`, `file`, `sha256`, `size`) and `latest`. |
| `.gitattributes`                      | Pins the JavaScript files to LF and marks `.wasm` as binary, so a checkout on any platform hashes to the same value.  |

`generate.py` hashes the content as stored in git: in the JavaScript files CRLF line endings count as LF,
the WebAssembly module is hashed byte for byte. The output is deterministic and carries no timestamps;
running it twice produces identical files. The `hashes/` folders are a local by-product and not
committed, `manifest.json` is.

```bash
python generate.py
```

The `users-chat` Additive clones this repository, runs `generate.py` exactly once per integrity run as
a subprocess of its own interpreter, recomputes every hash itself and only reports versions whose
hashes it could reproduce. A failing or non-reproducible run is reported as "reference unavailable",
never as a fresh result. Peers fetch `manifest.json` from this repository directly and compare it with
the files the host actually serves.

## Publishing a version

1. Copy the new `static/js/chat.js` to `crypto/v<N+1>.js`, or a new vodozemac build to
   `vodozemac/<x.y.z>/`.
2. Run `python generate.py` and commit the files together with `manifest.json`.


## HTTP and SRI digests

Every version also carries `http` (`sha256`, `sha384`, `sri`, `size`): the exact bytes a host serves and
a browser checks with Subresource Integrity. `sha256` and `size` above keep their meaning — the content
with CRLF counted as LF (binary artifacts byte for byte) — and their values did not change. A client
compares bytes it fetched over HTTP only with `http`, never with the normalised `sha256`.
`python -m pytest -q tests` checks reproducibility, the separation of both digests, a CRLF copy and a
flipped byte, and — next to the Additive — the served files against `latest`.

## What the hashes prove

A matching hash proves that a host serves the bytes published here — nothing more. It does not prove
that the published code is free of bugs, and it cannot prove what a host does on its server side.
A host that serves an older version than `latest` is reported as *outdated*, one that serves bytes that
match no version as a *reference mismatch*.

To compare by hand, download a file from the host and compare `sha256sum <file>` with `manifest.json`
(for `chat.js` and `vodozemac_bg.js` after converting CRLF line endings to LF, if your download tool
changed them).

## Licenses

`crypto/` and the tooling: see `LICENSE`. The files under `vodozemac/` are the build of
`@towns-protocol/vodozemac`, licensed under Apache-2.0 by their authors; they are reproduced here
unmodified so that their hashes can be checked.
