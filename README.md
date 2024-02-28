# go-signed-cookies

## Overview

This is a simple, semi-opiniated module for handling signed cookies in Go apps.

It is essentially a higher-level convenience API built on top of `github.com/gorilla/securecookie`.

To figure out how to use this module, please peruse the source (under 200 lines) and read the comments.

## Secrets

Secrets are expected to be 32 or 64 bytes and in base64 format.

You can generate a secret with:

```sh
openssl rand -base64 32 # or 64
```
