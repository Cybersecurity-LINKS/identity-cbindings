# identity-cbindings

This repository contains C-bindings for the [IOTA Identity](https://github.com/iotaledger/identity.rs) library to create and manage your own Self-Sovereign Identity in C.

## Build and Install

run `cargo build` to generate the `identity.h` file and save it in `bindings-demo` directory, then move it in `openssl-ssi-provider/common/include/prov/` of [openssl-ssi-provider](https://github.com/Cybersecurity-LINKS/openssl-ssi-provider)

## Usage

There is a `main.c` in `bindings-demo` in to test the generated APIs.
