# Lido Cosmos Validators Registry <!-- omit in toc -->

**NOTE**: Reference documentation for this contract is available [here](https://docs.cosmos.lido.fi/contracts/validators_registry).

The Validator Registry contract stores an approved validators whitelist.

The main query of the contract - `GetValidatorsForDelegation` returns a list of approved validators sorted by total_delegated amount.

The Hub uses this query to equally distribute delegations between validators.
