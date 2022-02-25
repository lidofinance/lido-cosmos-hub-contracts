// Copyright 2021 Anchor Protocol. Modified by Lido
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

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use std::string::FromUtf8Error;

use cosmwasm_std::{attr, from_binary, to_binary, Binary, Coin, CosmosMsg, Decimal, Deps, DepsMut, DistributionMsg, Env, MessageInfo, Order, QueryRequest, Response, StakingMsg, StdError, StdResult, Uint128, WasmMsg, WasmQuery, StakingQuery, DelegationResponse, AllDelegationsResponse, FullDelegation};

use crate::config::{execute_update_config, execute_update_params};
use crate::state::{
    all_unbond_history, get_unbond_requests, query_get_finished_amount, CONFIG, CURRENT_BATCH,
    GUARDIANS, PARAMETERS, STATE,
};
use crate::unbond::{execute_unbond_statom, execute_withdraw_unbonded};
use lido_cosmos_validators_registry::msg::QueryMsg as QueryValidators;

use crate::bond::execute_bond;
use basset::hub::{
    AllHistoryResponse, BondType, Config, ConfigResponse, CurrentBatch, CurrentBatchResponse,
    InstantiateMsg, MigrateMsg, Parameters, QueryMsg, State, StateResponse, UnbondHistoryResponse,
    UnbondRequestsResponse, WithdrawableUnbondedResponse,
};
use basset::hub::{Cw20HookMsg, ExecuteMsg};
use cw20::{Cw20QueryMsg, Cw20ReceiveMsg, TokenInfoResponse};
use lido_cosmos_rewards_dispatcher::msg::ExecuteMsg::DispatchRewards;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let sender = info.sender;

    // store config
    let data = Config {
        creator: sender,
        reward_dispatcher_contract: None,
        validators_registry_contract: None,
        statom_token_contract: None,
    };
    CONFIG.save(deps.storage, &data)?;

    // store state
    let state = State {
        statom_exchange_rate: Decimal::one(),
        last_unbonded_time: env.block.time.seconds(),
        last_processed_batch: 0u64,
        ..Default::default()
    };

    STATE.save(deps.storage, &state)?;

    // instantiate parameters
    let params = Parameters {
        epoch_period: msg.epoch_period,
        underlying_coin_denom: msg.underlying_coin_denom,
        unbonding_period: msg.unbonding_period,
        paused: Some(false),
    };

    PARAMETERS.save(deps.storage, &params)?;

    let batch = CurrentBatch {
        id: 1,
        requested_statom: Default::default(),
    };
    CURRENT_BATCH.save(deps.storage, &batch)?;

    let res = Response::new();
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Receive(msg) => receive_cw20(deps, env, info, msg),
        ExecuteMsg::BondForStAtom {} => execute_bond(deps, env, info, BondType::StAtom),
        ExecuteMsg::BondRewards {} => execute_bond(deps, env, info, BondType::BondRewards),
        ExecuteMsg::DispatchRewards {} => execute_dispatch_rewards(deps, env, info),
        ExecuteMsg::WithdrawUnbonded {} => execute_withdraw_unbonded(deps, env, info),
        ExecuteMsg::CheckSlashing {} => execute_slashing(deps, env),
        ExecuteMsg::UpdateParams {
            epoch_period,
            unbonding_period,
        } => execute_update_params(deps, env, info, epoch_period, unbonding_period),
        ExecuteMsg::UpdateConfig {
            owner,
            rewards_dispatcher_contract,
            validators_registry_contract,
            statom_token_contract,
        } => execute_update_config(
            deps,
            env,
            info,
            owner,
            rewards_dispatcher_contract,
            statom_token_contract,
            validators_registry_contract,
        ),
        ExecuteMsg::RedelegateProxy {
            src_validator,
            redelegations,
        } => execute_redelegate_proxy(deps, env, info, src_validator, redelegations),
        ExecuteMsg::PauseContracts {} => execute_pause_contracts(deps, env, info),
        ExecuteMsg::UnpauseContracts {} => execute_unpause_contracts(deps, env, info),
        ExecuteMsg::AddGuardians { addresses } => execute_add_guardians(deps, env, info, addresses),
        ExecuteMsg::RemoveGuardians { addresses } => {
            execute_remove_guardians(deps, env, info, addresses)
        }
        ExecuteMsg::ReceiveTokenizedShare {validator} => receive_tokenized_share(deps, env, info, validator)
    }
}

pub fn receive_tokenized_share(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    validator: String,
) -> StdResult<Response> {
    // Check that the validator specified in the message is a whitelisted validator.
    {
        let validators_registry_contract = if let Some(v) = config.validators_registry_contract {
            v
        } else {
            return Err(StdError::generic_err(
                "Validators registry contract address is empty",
            ));
        };
        let is_known_validator: bool =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: validators_registry_contract.to_string(),
                msg: to_binary(&QueryValidators::HasValidator { address: validator.clone() })?,
            }))?;
        if !is_known_validator {
            return Err(StdError::generic_err(
                "Validator is not whitelisted",
            ));
        }
    }

    // Take all tokenized shares of the specified validator's delegations.
    // Note: tokenized share denom looks like this:
    // cosmosvaloper1qp49fdjtlsrv6jkx3gc8urp2ncg88s6mcversm12345, where 12345 is the recordId
    // (see https://github.com/iqlusioninc/liquidity-staking-module/blob/master/x/staking/keeper/msg_server.go#L436)
    let vouchers: Vec<Coin> = info
        .funds
        .iter()
        .filter(|x| x.denom.contains(validator.clone()) && x.amount > Uint128::zero())
        .collect();

    for voucher in vouchers {
        let mut messages: Vec<CosmosMsg> = vec![];
        // Note: the RedeemTokensForShares message is not implemented yet.
        messages.push(cosmwasm_std::CosmosMsg::Staking(StakingMsg::RedeemTokensForShares {
            delegator_address: validator.clone(),
            amount: voucher,
        }));

        // Unfortunately, the response for RedeemTokensForShares does not contain any
        // information at all, so we'll need to calculate the returned amount ourselves.

        // We need to get the tokenized share module account somehow to query for the
        // delegation. The module account is recorded as fmt.Sprintf("tokenizeshare_%d", recordId)
        // during the creation of a share, ad there is no direct way to get tokenizedShareRecord
        // from the liquid staking module, so we'll need to extract it from token denom
        // in a dirty way.
        let delegator = if let Some(acc) = voucher.denom.clone()
            .split(validator.clone())
            .next_back() {
            acc
        } else {
            return Err(StdError::generic_err(
                "Failed to get recordId from tokenized share {}".format(voucher.denom.clone()),
            ));
        };

        // Now we need to get the delegation info.
        let delegation_response: DelegationResponse = deps.querier.query(&QueryRequest::Staking(StakingQuery::Delegation {
            delegator: delegator.to_string(),
            validator: validator.clone(),
        }))?;

        let delegation: FullDelegation = if let Some(d) = delegation_response.delegation {
            d
        } else {
            return Err(StdError::generic_err(
                "Failed to find delegation for {}".format(voucher.denom.clone()),
            ));
        };


    }


    Ok(Response::new())
}

pub fn execute_add_guardians(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    guardians: Vec<String>,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.creator {
        return Err(StdError::generic_err("unauthorized"));
    }

    for guardian in &guardians {
        GUARDIANS.save(deps.storage, guardian.clone(), &true)?;
    }

    Ok(Response::new()
        .add_attributes(vec![attr("action", "add_guardians")])
        .add_attributes(guardians.iter().map(|g| attr("value", g))))
}

pub fn execute_remove_guardians(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    guardians: Vec<String>,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.creator {
        return Err(StdError::generic_err("unauthorized"));
    }

    for guardian in &guardians {
        GUARDIANS.remove(deps.storage, guardian.clone());
    }

    Ok(Response::new()
        .add_attributes(vec![attr("action", "remove_guardians")])
        .add_attributes(guardians.iter().map(|g| attr("value", g))))
}

pub fn execute_pause_contracts(deps: DepsMut, _env: Env, info: MessageInfo) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if !(info.sender == config.creator || GUARDIANS.has(deps.storage, info.sender.to_string())) {
        return Err(StdError::generic_err("unauthorized"));
    }

    let mut params: Parameters = PARAMETERS.load(deps.storage)?;
    params.paused = Some(true);

    PARAMETERS.save(deps.storage, &params)?;

    let res = Response::new().add_attributes(vec![attr("action", "pause_contracts")]);
    Ok(res)
}

pub fn execute_unpause_contracts(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.creator {
        return Err(StdError::generic_err("unauthorized"));
    }

    let mut params: Parameters = PARAMETERS.load(deps.storage)?;
    params.paused = Some(false);

    PARAMETERS.save(deps.storage, &params)?;

    let res = Response::new().add_attributes(vec![attr("action", "unpause_contracts")]);
    Ok(res)
}

pub fn execute_redelegate_proxy(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    src_validator: String,
    redelegations: Vec<(String, Coin)>,
) -> StdResult<Response> {
    let sender_contract_addr = info.sender;
    let conf = CONFIG.load(deps.storage)?;
    let validators_registry_contract = conf.validators_registry_contract.ok_or_else(|| {
        StdError::generic_err("the validator registry contract must have been registered")
    })?;

    if sender_contract_addr != validators_registry_contract && sender_contract_addr != conf.creator
    {
        return Err(StdError::generic_err("unauthorized"));
    }

    let messages: Vec<CosmosMsg> = redelegations
        .into_iter()
        .map(|(dst_validator, amount)| {
            cosmwasm_std::CosmosMsg::Staking(StakingMsg::Redelegate {
                src_validator: src_validator.clone(),
                dst_validator,
                amount,
            })
        })
        .collect();

    let res = Response::new().add_messages(messages);

    Ok(res)
}

/// CW20 token receive handler.
pub fn receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> StdResult<Response> {
    let params: Parameters = PARAMETERS.load(deps.storage)?;
    if params.paused.unwrap_or(false) {
        return Err(StdError::generic_err("the contract is temporarily paused"));
    }

    let contract_addr = deps.api.addr_validate(info.sender.as_str())?;

    // only token contract can execute this message
    let conf = CONFIG.load(deps.storage)?;

    let statom_contract_addr = if let Some(st) = conf.statom_token_contract {
        st
    } else {
        return Err(StdError::generic_err(
            "the statom token contract must have been registered",
        ));
    };

    match from_binary(&cw20_msg.msg)? {
        Cw20HookMsg::Unbond {} => {
            if contract_addr == statom_contract_addr {
                execute_unbond_statom(deps, env, cw20_msg.amount, cw20_msg.sender)
            } else {
                Err(StdError::generic_err("unauthorized"))
            }
        }
    }
}

/// Permissionless
pub fn execute_dispatch_rewards(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
) -> StdResult<Response> {
    let params: Parameters = PARAMETERS.load(deps.storage)?;
    if params.paused.unwrap_or(false) {
        return Err(StdError::generic_err("the contract is temporarily paused"));
    }

    let config = CONFIG.load(deps.storage)?;
    let reward_addr_dispatcher = config
        .reward_dispatcher_contract
        .ok_or_else(|| StdError::generic_err("the reward contract must have been registered"))?;

    // Send withdraw message
    let mut withdraw_msgs = withdraw_all_rewards(&deps, env.contract.address.to_string())?;
    let mut messages: Vec<CosmosMsg> = vec![];
    messages.append(&mut withdraw_msgs);

    messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: reward_addr_dispatcher.to_string(),
        msg: to_binary(&DispatchRewards {})?,
        funds: vec![],
    }));

    let res = Response::new()
        .add_messages(messages)
        .add_attributes(vec![attr("action", "dispatch_rewards")]);
    Ok(res)
}

/// Create withdraw requests for all validators
fn withdraw_all_rewards(deps: &DepsMut, delegator: String) -> StdResult<Vec<CosmosMsg>> {
    let mut messages: Vec<CosmosMsg> = vec![];

    let delegations = deps.querier.query_all_delegations(delegator)?;

    if !delegations.is_empty() {
        for delegation in delegations {
            let msg: CosmosMsg =
                CosmosMsg::Distribution(DistributionMsg::WithdrawDelegatorReward {
                    validator: delegation.validator,
                });
            messages.push(msg);
        }
    }

    Ok(messages)
}

fn query_actual_state(deps: Deps, env: Env) -> StdResult<State> {
    let mut state = STATE.load(deps.storage)?;
    let delegations = deps.querier.query_all_delegations(env.contract.address)?;
    if delegations.is_empty() {
        return Ok(state);
    }

    //read params
    let params = PARAMETERS.load(deps.storage)?;
    let coin_denom = params.underlying_coin_denom;

    // Check the actual bonded amount
    let mut actual_total_bonded = Uint128::zero();
    for delegation in &delegations {
        if delegation.amount.denom == coin_denom {
            actual_total_bonded += delegation.amount.amount;
        }
    }

    // Check the amount that contract thinks is bonded
    if state.total_bond_statom_amount.is_zero() {
        return Ok(state);
    }

    // Need total issued for updating the exchange rate
    state.total_statom_issued = query_total_statom_issued(deps)?;
    let current_batch = CURRENT_BATCH.load(deps.storage)?;
    let current_requested_statom = current_batch.requested_statom;

    if state.total_bond_statom_amount.u128() > actual_total_bonded.u128() {
        state.total_bond_statom_amount = actual_total_bonded;
    }
    state.update_statom_exchange_rate(state.total_statom_issued, current_requested_statom);
    Ok(state)
}

/// Check whether slashing has happened
/// This is used for checking slashing while bonding or unbonding
pub fn slashing(deps: &mut DepsMut, env: Env) -> StdResult<State> {
    let state = query_actual_state(deps.as_ref(), env)?;

    STATE.save(deps.storage, &state)?;

    Ok(state)
}

/// Handler for tracking slashing
pub fn execute_slashing(mut deps: DepsMut, env: Env) -> StdResult<Response> {
    let params: Parameters = PARAMETERS.load(deps.storage)?;
    if params.paused.unwrap_or(false) {
        return Err(StdError::generic_err("the contract is temporarily paused"));
    }

    // call slashing and
    let state = slashing(&mut deps, env)?;
    Ok(Response::new().add_attributes(vec![
        attr("action", "check_slashing"),
        attr(
            "new_statom_exchange_rate",
            state.statom_exchange_rate.to_string(),
        ),
    ]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::State {} => to_binary(&query_state(deps, env)?),
        QueryMsg::CurrentBatch {} => to_binary(&query_current_batch(deps)?),
        QueryMsg::WithdrawableUnbonded { address } => {
            to_binary(&query_withdrawable_unbonded(deps, address, env)?)
        }
        QueryMsg::Parameters {} => to_binary(&query_params(deps)?),
        QueryMsg::UnbondRequests { address } => to_binary(&query_unbond_requests(deps, address)?),
        QueryMsg::AllHistory { start_from, limit } => {
            to_binary(&query_unbond_requests_limitation(deps, start_from, limit)?)
        }
        QueryMsg::Guardians => to_binary(&query_guardians(deps)?),
    }
}

fn query_guardians(deps: Deps) -> StdResult<Vec<String>> {
    let guardians = GUARDIANS.keys(deps.storage, None, None, Order::Ascending);
    let guardians_decoded: Result<Vec<String>, FromUtf8Error> =
        guardians.map(String::from_utf8).collect();
    Ok(guardians_decoded?)
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    let mut reward_dispatcher: Option<String> = None;
    let mut validators_contract: Option<String> = None;
    let mut statom_token: Option<String> = None;
    if config.reward_dispatcher_contract.is_some() {
        reward_dispatcher = Some(config.reward_dispatcher_contract.unwrap().to_string());
    }
    if config.statom_token_contract.is_some() {
        statom_token = Some(config.statom_token_contract.unwrap().to_string());
    }
    if config.validators_registry_contract.is_some() {
        validators_contract = Some(config.validators_registry_contract.unwrap().to_string());
    }

    Ok(ConfigResponse {
        owner: config.creator.to_string(),
        reward_dispatcher_contract: reward_dispatcher,
        validators_registry_contract: validators_contract,
        statom_token_contract: statom_token,
    })
}

fn query_state(deps: Deps, env: Env) -> StdResult<StateResponse> {
    let state = query_actual_state(deps, env)?;
    let res = StateResponse {
        statom_exchange_rate: state.statom_exchange_rate,
        total_bond_statom_amount: state.total_bond_statom_amount,
        prev_hub_balance: state.prev_hub_balance,
        last_unbonded_time: state.last_unbonded_time,
        last_processed_batch: state.last_processed_batch,
    };
    Ok(res)
}

fn query_current_batch(deps: Deps) -> StdResult<CurrentBatchResponse> {
    let current_batch = CURRENT_BATCH.load(deps.storage)?;
    Ok(CurrentBatchResponse {
        id: current_batch.id,
        requested_statom: current_batch.requested_statom,
    })
}

fn query_withdrawable_unbonded(
    deps: Deps,
    address: String,
    env: Env,
) -> StdResult<WithdrawableUnbondedResponse> {
    let params = PARAMETERS.load(deps.storage)?;
    let historical_time = env.block.time.seconds() - params.unbonding_period;
    let all_requests = query_get_finished_amount(deps.storage, address, historical_time)?;

    let withdrawable = WithdrawableUnbondedResponse {
        withdrawable: all_requests,
    };
    Ok(withdrawable)
}

fn query_params(deps: Deps) -> StdResult<Parameters> {
    PARAMETERS.load(deps.storage)
}

pub(crate) fn query_total_statom_issued(deps: Deps) -> StdResult<Uint128> {
    let token_address = CONFIG
        .load(deps.storage)?
        .statom_token_contract
        .ok_or_else(|| StdError::generic_err("token contract must have been registered"))?;
    let token_info: TokenInfoResponse =
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: token_address.to_string(),
            msg: to_binary(&Cw20QueryMsg::TokenInfo {})?,
        }))?;
    Ok(token_info.total_supply)
}

fn query_unbond_requests(deps: Deps, address: String) -> StdResult<UnbondRequestsResponse> {
    let requests = get_unbond_requests(deps.storage, address.clone())?;
    let res = UnbondRequestsResponse { address, requests };
    Ok(res)
}

fn query_unbond_requests_limitation(
    deps: Deps,
    start: Option<u64>,
    limit: Option<u32>,
) -> StdResult<AllHistoryResponse> {
    let requests = all_unbond_history(deps.storage, start, limit)?;
    let requests_responses = requests
        .iter()
        .map(|r| UnbondHistoryResponse {
            batch_id: r.batch_id,
            time: r.time,

            statom_amount: r.statom_amount,
            statom_applied_exchange_rate: r.statom_applied_exchange_rate,
            statom_withdraw_rate: r.statom_withdraw_rate,

            released: r.released,
        })
        .collect();

    let res = AllHistoryResponse {
        history: requests_responses,
    };
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::new())
}
