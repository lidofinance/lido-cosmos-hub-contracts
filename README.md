# Lido Terra Contracts

This monorepository contains the source code for the smart contracts implementing bAsset Protocol on the [Terra](https://terra.money) blockchain.

You can find information about the architecture, usage, and function of the smart contracts on the official documentation [site](https://lidofinance.github.io/terra-docs/).


## Contracts
| Contract                                            | Reference                                              | Description                                                                                                                        |
| --------------------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |


## Development

### Environment Setup

- Rust v1.55.0+
- `wasm32-unknown-unknown` target
- Docker

1. Install `rustup` via https://rustup.rs/

2. Run the following:

```sh
rustup default stable
rustup target add wasm32-unknown-unknown
```

3. Make sure [Docker](https://www.docker.com/) is installed

### Unit Tests

Each contract contains Rust unit tests embedded within the contract source directories. You can run:

```sh
make test
```

### Generating schema

```sh
make schema
```

### Production

For production builds, run the following:

```sh
make build
```

This performs several optimizations which can significantly reduce the final size of the contract binaries, which will be available inside the `artifacts/` directory.

## Documentation

Check you the documentation at https://lidofinance.github.io/terra-docs/.

## License

Copyright 2021 Lido

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
