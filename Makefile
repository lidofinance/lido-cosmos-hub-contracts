.PHONY: schema test clippy build

TOOLCHAIN := "1.58.1"

schema:
	@find contracts/* -maxdepth 0 -type d \( ! -name . \) -exec bash -c "cd '{}' && cargo +${TOOLCHAIN} schema" \;

test:
	@cargo test

clippy:
	@cargo +${TOOLCHAIN} clippy --all --all-targets -- -D warnings

build: schema clippy test
	@./build_release.sh