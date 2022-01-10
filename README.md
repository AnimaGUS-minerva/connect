Hermes Connect --- RFC8994 Autonomic Control Plane
--------------------------------------------------

An RFC8994 implementation Rust for using Linux network namespace to implement the
RFC8994 Autonomic Control Plane.

Hermes Connect is a supervisor deamon for deploying an RFC8994 Autonomic Control Plane (ACP) to a Linux based host.

(It is designed to use as few OS-specific resources as possible in order to be deployable to as many environments as possible.  Since the ACP provides virtual out-of-band access to the host, dependancies upon the host environment creates more risk that the ACP might not operate when needed)

In order to operate, it requires some additional modules:
* An IPsec/IKEv2 daemon, such as OpenswanX.
* An RFC6550 RPL daemon, such as Unstrung.
* An RFC8995 BRSKI client
* A manufacturer deployed IDevID certificate and private key.

The file [Architecture](doc/Architecture.md) provides some context for how each component goes together.




[![Rust](https://github.com/AnimaGUS-minerva/connect/actions/workflows/rust.yml/badge.svg)](https://github.com/AnimaGUS-minerva/connect/actions/workflows/rust.yml)




