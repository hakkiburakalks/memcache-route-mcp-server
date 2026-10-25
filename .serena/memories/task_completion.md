Run from workspace root before calling a task done:
1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. If protocol/core behaviour changed: run the Docker compat suite across memcached versions.
