# Lido Cosmos Validators Registry

The Validator Registry contract stores an approved validators whitelist.

The main query of the contract - `GetValidatorsForDelegation` returns a list of approved validators sorted by total_delegated amount.

The Hub uses this query to equally distribute delegations between validators.

# Config
|Key |Type|Description|
|-----|--------|-----------|
|owner|Addr       |Owner of the contract|
|hub_contract  |Addr      |Contract address of Hub|

```json
{
  "owner": "cosm1...",
  "hub_contract": "cosm1..."
}
```
# Validator
|Key |Type|Description|
|-----|--------|-----------|
|total_delegated|Uint128       |Total amount of tokens delegated to this validator from the Hub address|
|address  |String      |Operator address|

```json
{
  "total_delegated": "10000",
  "address": "cosmvaloper1..."
}
```

# InitMsg
```rust
pub struct InstantiateMsg {
    pub registry: Vec<Validator>,
    pub hub_contract: String,
}
```
```json
{
  "registry": [
    {
      "address": "cosmvaloper1..."
    },
    {
      "address": "cosmvaloper1..."
    }
  ],
  "hub_contract": "cosm1..."
}
```
|Key|	Type|	Description|
|---|-------|--------------|
|hub_contract|Addr|Contract address of Hub|
|registry|Vec<Validator>|List of whitelisted validators|

# ExecuteMsg
## AddValidator
Adds a validator to the registry.

Can only be executed by the owner.
```rust
pub enum ExecuteMsg {
    AddValidator {
        validator: Validator
    },
}
```
```json
{
  "add_validator": {
    "validator": {
      "address": "cosmvaloper1..."
    }
  }
}
```
|Key|	Type|	Description|
|----|------|--------------|
|validator	|Validator	|Validator to add to the registry|

## RemoveValidator
Removes a validator from the registry.

Can only be executed by the owner.
```rust
pub enum ExecuteMsg { 
    RemoveValidator {
        address: String
    },
}
```
```json
{
  "remove_validator": {
    "address": "cosmvaloper1..."
  }
}
```
|Key	|Type	|Description|
|-------|-------|-----------|
|address|	Validator|	Address of a to remove from the registry|

## UpdateConfig
Updates a registry's configuration.

Can only be issued by the owner.

```rust
pub enum ExecuteMsg {
    UpdateConfig {
        owner: Option<String>,
        hub_contract: Option<String>,
    },
}
```
```json
{
  "owner": "cosm1...",
  "hub_contract": "cosm1..."
}
```
|Key	|Type	|Description|
|-------|-------|-----------|
|owner*	|Addr	|New owner of the contract|
|hub_contract*	|Addr	|New contract address of Hub|
\* = optional

# QueryMsg
## GetValidatorsForDelegation
Returns validators sorted by total_delegated amount.
```rust
pub enum QueryMsg {
    GetValidatorsForDelegation {},
}
```
```json
{
  "get_validators_for_delegation": {}
}
```
Returns a list of Validator:
```json
[
  {
    "total_delegated": "30000",
    "address": "cosmvaloper1..."
  },
  {
    "total_delegated": "20000",
    "address": "cosmvaloper1..."
  },
  {
    "total_delegated": "10000",
    "address": "cosmvaloper1..."
  }
]
```
## Config
Returns the current configuration of the registry.
```rust
pub enum QueryMsg {
    Config {},
}
```
```json
{
  "config": {}
}
```
Returns a Config struct.