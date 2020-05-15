# Tracing in E2EE Messaging

_Rust implementation of message tracing for E2E encrypted messaging_

**CCS 2019:**
Nirvan Tyagi, Ian Miers, Thomas Ristenpart. _Traceback for End-to-End Encrypted Messaging_. CCS 2019.

**ePrint:**
Nirvan Tyagi, Ian Miers, Thomas Ristenpart. _Traceback for End-to-End Encrypted Messaging_. Cryptology ePrint Archive, Report 2019/981. http://eprint.iacr.org/2019/981. 2019.

## Overview

This repository is organized as a Rust workspace including two crates.
* [`tracing`](tracing): Rust library that provides client and server algorithms for path and tree traceback
* [`tracing-server`](tracing-server): Rust binary that provides a server implementation to process messages and perform traceback.

## Installation/Build

The server binary compiles on the `nightly` toolchain of the Rust compiler, while the library can compile on `stable`.
Since both packages will work with `nightly`, we will describe the installation with `nightly`.
Install the latest version of Rust using `rustup` by following the instructions [here](https://rustup.rs/).
Then, install the Rust `nightly` toolchain:
```bash
rustup install nightly
```

Clone the repository:
```bash
git clone https://github.com/nirvantyagi/tracing.git
cd tracing/
```

Either set your default Rust toolchain to `nightly` or create a directory specific override for `tracing/`:
```bash
rustup default nightly
```
```bash
rustup override set nightly
```

Build using `cargo`:
```bash
cargo build
```

## Tests and Benchmarks

The `tracing` library comes with a suite of tests and benchmarks for the path and tree traceback protocol implementations.
To run the tests, unfortunately, you must first spin up a Redis instance. 
Install Redis by following the instructions [here](https://redis.io/topics/quickstart).
In a separate terminal, start a Redis server listening on port 6379 (default configuration).
```bash
redis-server
```

Due to tests clearing the Redis database after their execution, the tests must be run sequentially as follows where `cargo test` runs all tests and benchmarks and `cargo bench` runs only benchmarks:
```bash
cargo test -p tracing -- --test-threads=1
cargo bench -p tracing -- --test-threads=1
```

