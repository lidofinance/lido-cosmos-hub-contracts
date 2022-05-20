// Copyright 2021 Lido
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128,
};

use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::registry::{Config, ValidatorResponse, CONFIG, REGISTRY};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    CONFIG.save(
        deps.storage,
        &Config {
            zone: msg.zone,
            owner: info.sender,
            hub_contract: deps.api.addr_validate(msg.hub_contract.as_str())?,
        },
    )?;

    for v in msg.registry {
        // FIXME: update the comment below with correct prefixes after cosmwasm in cosmos hub will have been released
        // deps.api.addr_validate validates only terra1 prefixed addresses
        // validators terravaloper1 throws an error, but we can use query_validator witch sucessefully validates valoper address
        deps.querier.query_validator(&v.address)?;
        REGISTRY.save(deps.storage, v.address.as_str().as_bytes(), &v)?;
    }

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::ApplicationRequest { address } => application_request(deps, env, info, address),
        ExecuteMsg::KickValidator { address } => kick_validator(deps, env, info, address),
        ExecuteMsg::PromoteValidator { address, weight } => {
            promote_validator(deps, env, info, address, weight)
        }
        ExecuteMsg::ProcessApplications {} => process_applications(deps, env, info),
        ExecuteMsg::UpdateConfig {
            owner,
            hub_contract,
        } => execute_update_config(deps, env, info, owner, hub_contract),
    }
}

pub fn application_request(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    address: String,
) -> StdResult<Response> {
    //save validator address into pending list
    //register query to get validator params
    Ok(Response::default())
}

pub fn process_applications(deps: DepsMut, _env: Env, _info: MessageInfo) -> StdResult<Response> {
    //get pending list
    //process it
    Ok(Response::default())
}

pub fn promote_validator(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    address: String,
    weight: Uint128,
) -> StdResult<Response> {
    //if validator in pemission-less list
    //move validator from pemission-less list to permissioned list
    //otherwise just update weight
    Ok(Response::default())
}

/// Update the config. Update the owner and hub contract address.
/// Only creator/owner is allowed to execute
pub fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: Option<String>,
    hub_contract: Option<String>,
) -> StdResult<Response> {
    // only owner must be able to send this message.
    let config = CONFIG.load(deps.storage)?;
    let owner_address = config.owner;
    if info.sender != owner_address {
        return Err(StdError::generic_err("unauthorized"));
    }

    if let Some(o) = owner {
        let owner_raw = deps.api.addr_validate(&o)?;

        CONFIG.update(deps.storage, |mut last_config| -> StdResult<_> {
            last_config.owner = owner_raw;
            Ok(last_config)
        })?;
    }

    if let Some(hub) = hub_contract {
        let hub_raw = deps.api.addr_validate(&hub)?;

        CONFIG.update(deps.storage, |mut last_config| -> StdResult<_> {
            last_config.hub_contract = hub_raw;
            Ok(last_config)
        })?;
    }

    Ok(Response::default())
}

pub fn kick_validator(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    validator_address: String,
) -> StdResult<Response> {
    //check if validator is in the registries
    //checks validator params
    //get active redelegations
    //if no active redelegations {
    //  get delegated amount
    //  redelegate
    //}
    let res = Response::new();
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetValidatorsForDelegation {} => {
            let mut validators = query_validators(deps)?;
            validators.sort_by(|v1, v2| v1.total_delegated.cmp(&v2.total_delegated));
            to_binary(&validators)
        }
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::HasValidator { address } => to_binary(&query_has_validator(deps, address)),
        QueryMsg::GetLargestValidator {} => to_binary(&query_largest_validator(deps)?),
    }
}

fn query_config(deps: Deps) -> StdResult<Config> {
    let config = CONFIG.load(deps.storage)?;
    Ok(config)
}

fn query_has_validator(deps: Deps, address: String) -> bool {
    REGISTRY.has(deps.storage, address.as_bytes())
}

fn query_largest_validator(deps: Deps) -> StdResult<ValidatorResponse> {
    let config = CONFIG.load(deps.storage)?;
    let hub_address = config.hub_contract;

    let mut largest_validator_address = String::new();
    let mut largest_delegation_amount = Uint128::zero();
    for delegation in deps.querier.query_all_delegations(&hub_address)? {
        if delegation.amount.amount > largest_delegation_amount {
            largest_validator_address = delegation.validator;
            largest_delegation_amount = delegation.amount.amount;
        }
    }

    if largest_delegation_amount.is_zero() {
        return Err(StdError::generic_err("No delegations found"));
    }

    Ok(ValidatorResponse {
        address: largest_validator_address,
        total_delegated: largest_delegation_amount,
    })
}

fn query_validators(deps: Deps) -> StdResult<Vec<ValidatorResponse>> {
    let config = CONFIG.load(deps.storage)?;
    let hub_address = config.hub_contract;

    let mut delegations = HashMap::new();
    for delegation in deps.querier.query_all_delegations(&hub_address)? {
        delegations.insert(delegation.validator, delegation.amount.amount);
    }

    let mut validators: Vec<ValidatorResponse> = vec![];
    for item in REGISTRY.range(deps.storage, None, None, cosmwasm_std::Order::Ascending) {
        let mut validator = ValidatorResponse {
            total_delegated: Default::default(),
            address: item?.1.address,
        };
        // TODO: check that cosmos cosmwasm module has this bug or not
        // There is a bug in terra/core.
        // The bug happens when we do query_delegation() but there are no delegation pair (delegator-validator)
        // but query_delegation() fails with a parse error cause terra/core returns an empty FullDelegation struct
        // instead of a nil pointer to the struct.
        // https://github.com/terra-money/core/blob/58602320d2907814cfccdf43e9679468bb4bd8d3/x/staking/wasm/interface.go#L227
        // So we do query_all_delegations() instead of query_delegation().unwrap()
        // and try to find delegation in the returned vec
        validator.total_delegated = *delegations
            .get(&validator.address)
            .unwrap_or(&Uint128::zero());
        validators.push(validator);
    }
    Ok(validators)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}
