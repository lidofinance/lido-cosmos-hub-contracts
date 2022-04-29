.PHONY: schema test clippy proto-gen build

schema:
	@find contracts/* -maxdepth 0 -type d \( ! -name . \) -exec bash -c "cd '{}' && cargo schema" \;

test:
	@cargo test

clippy:
	@cargo clippy --all --all-targets -- -D warnings

proto-gen:
	@protoc --rust_out ./contracts/lido_cosmos_hub/src/ ./contracts/lido_cosmos_hub/src/tokenize_share_record.proto

build: schema clippy test
	@./build_release.sh
