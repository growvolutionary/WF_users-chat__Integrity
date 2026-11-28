# users-chat browser cryptography integrity

This repository holds the version history of the static file the `users-chat` Additive serves for its
end-to-end encryption in the browser, with its correlating hashes:

| Artifact            | Served at                 | Meaning                              |
|---------------------|---------------------------|--------------------------------------|
| `users-chat_crypto` | `/chat/static/js/chat.js` | All browser cryptography of the chat |

The Olm and Megolm primitives (vodozemac) are not part of this repository: the `users` Additive serves and
pins them and its own integrity repository covers them. `chat.js` only uses them.

## Contents

| Path             | Meaning                                                                                                                |
|------------------|------------------------------------------------------------------------------------------------------------------------|
| `crypto/v<N>.js` | The published source of every version of `static/js/chat.js`.                                                          |
| `generate.py`    | Computes the SHA-256 of every version and writes `manifest.json` (and `<folder>/hashes/`).                             |
| `manifest.json`  | The public reference, format 2: per artifact one entry per version (`version`, `file`, `sha256`, `size`) and `latest`. |
| `sync.py`        | Maintainer step: copies the served `static/js/chat.js` into the latest open version and runs `generate.py`.            |
| `.gitattributes` | Pins the JavaScript files to LF, so a checkout on any platform hashes to the same value.                               |

`generate.py` hashes the content as stored in git: in the JavaScript files CRLF line endings count as LF. The output is deterministic and carries no timestamps;
running it twice produces identical files. The `hashes/` folders are a local by-product and not
committed, `manifest.json` is.

```bash
python generate.py
python -m pytest -q tests
```

With this repository checked out as `integrity/` inside the Additive, `python -I sync.py` copies the
served script with LF line endings into the latest version and regenerates `manifest.json`. A version
listed in its `FROZEN` map is never rewritten; a changed script then becomes `v<N+1>.js`.

The `users-chat` Additive clones this repository, runs `generate.py` exactly once per integrity run as
a subprocess of its own interpreter, recomputes every hash itself and only reports versions whose
hashes it could reproduce. A failing or non-reproducible run is reported as "reference unavailable",
never as a fresh result. Peers fetch `manifest.json` from this repository directly and compare it with
the files the host actually serves.

## Publishing a version

1. Copy the new `static/js/chat.js` to `crypto/v<N+1>.js`.
2. Run `python generate.py` and commit the files together with `manifest.json`.


## HTTP and SRI digests

Every version also carries `http` (`sha256`, `sha384`, `sri`, `size`): the exact bytes a host serves and
a browser checks with Subresource Integrity. `sha256` and `size` above keep their meaning — the content
with CRLF counted as LF — and their values did not change. A client
compares bytes it fetched over HTTP only with `http`, never with the normalised `sha256`.
`python -m pytest -q tests` checks reproducibility, the separation of both digests, a CRLF copy and a
flipped byte, and — next to the Additive — the served files against `latest`.

## What the hashes prove

A matching hash proves that a host serves the bytes published here — nothing more. It does not prove
that the published code is free of bugs, and it cannot prove what a host does on its server side.
A host that serves an older version than `latest` is reported as *outdated*, one that serves bytes that
match no version as a *reference mismatch*.

To compare by hand, download a file from the host and compare `sha256sum <file>` with `manifest.json`
(for `chat.js` after converting CRLF line endings to LF, if your download tool changed them).

## License

`crypto/` and the tooling: see `LICENSE`.
