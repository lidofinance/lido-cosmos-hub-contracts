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
use cosmwasm_std::{
    attr, from_binary, to_binary, BankMsg, Binary, Coin, CosmosMsg, Decimal, Deps, DepsMut,
    DistributionMsg, Env, MessageInfo, QueryRequest, Reply, Response, StakingMsg, StdError,
    StdResult, SubMsgResult, Uint128, WasmMsg, WasmQuery,
};

use crate::config::{execute_update_config, execute_update_params};
use crate::state::{
    query_all_guardians, CONFIG, GUARDIANS, PARAMETERS, STATE, TOKENIZED_SHARE_RECIPIENT,
};

use crate::bond::execute_bond;
use crate::tokenize_share_record::MsgTokenizeSharesResponse;
use crate::tokenized::{execute_unbond_statom, receive_tokenized_share, TOKENIZE_SHARES_REPLY_ID};
use basset::hub::{
    is_paused, BondType, Config, ConfigResponse, InstantiateMsg, MigrateMsg, Parameters,
    PausedRequest, QueryMsg, State, StateResponse,
};
use basset::hub::{Cw20HookMsg, ExecuteMsg};
use cw20::{Cw20QueryMsg, Cw20ReceiveMsg, TokenInfoResponse};
use lido_cosmos_rewards_dispatcher::msg::ExecuteMsg::DispatchRewards;
use std::str::FromStr;

pub const MAX_PAUSE_DURATION: u64 = 100800; // approximately 1 week

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
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
        last_processed_batch: 0u64,
        ..Default::default()
    };

    STATE.save(deps.storage, &state)?;

    // instantiate parameters
    let params = Parameters {
        underlying_coin_denom: msg.underlying_coin_denom,
        paused_until: None,
        max_burn_ratio: msg.max_burn_ratio,
    };

    PARAMETERS.save(deps.storage, &params)?;

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
        ExecuteMsg::CheckSlashing {} => execute_slashing(deps, env),
        ExecuteMsg::UpdateParams { max_burn_ratio } => {
            execute_update_params(deps, env, info, max_burn_ratio)
        }
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
        ExecuteMsg::PauseContracts { duration } => {
            execute_pause_contracts(deps, env, info, duration)
        }
        ExecuteMsg::UnpauseContracts {} => execute_unpause_contracts(deps, env, info),
        ExecuteMsg::AddGuardians { addresses } => execute_add_guardians(deps, env, info, addresses),
        ExecuteMsg::RemoveGuardians { addresses } => {
            execute_remove_guardians(deps, env, info, addresses)
        }
        ExecuteMsg::ReceiveTokenizedShare {} => receive_tokenized_share(deps, env, info),
    }
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
        deps.api.addr_validate(guardian)?;
        GUARDIANS.save(deps.storage, guardian.clone(), &true)?;
    }

    Ok(Response::new()
        .add_attributes(vec![attr("action", "add_guardians")])
        .add_attributes(guardians.iter().map(|g| attr("address", g))))
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

pub fn execute_pause_contracts(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    duration: u64,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if !(info.sender == config.creator || GUARDIANS.has(deps.storage, info.sender.to_string())) {
        return Err(StdError::generic_err("unauthorized"));
    }

    if duration == 0 {
        return Err(StdError::generic_err(
            "pause duration should be greater than zero",
        ));
    }
    if duration > MAX_PAUSE_DURATION {
        return Err(StdError::generic_err(format!(
            "pause duration is too big: it's only possible to pause contracts for {} blocks or less",
            MAX_PAUSE_DURATION
        )));
    }

    let pause_until = env.block.height + duration;

    let mut params: Parameters = PARAMETERS.load(deps.storage)?;
    if let Some(already_paused_until) = params.paused_until {
        if already_paused_until >= pause_until {
            return Err(StdError::generic_err(
                "contracts are already paused for a greater or equal duration",
            ));
        }
    }

    params.paused_until = Some(pause_until);
    PARAMETERS.save(deps.storage, &params)?;

    let res = Response::new().add_attributes(vec![
        attr("action", "pause_contracts"),
        attr("pause_for", format!("{}", duration)),
        attr("pause_until", format!("{}", pause_until)),
    ]);
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
    params.paused_until = None;

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

    if !(sender_contract_addr == validators_registry_contract
        || sender_contract_addr == conf.creator)
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
    if is_paused(
        deps.as_ref(),
        env.clone(),
        PausedRequest::FromHubParameters(params),
    )? {
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
    if is_paused(
        deps.as_ref(),
        env.clone(),
        PausedRequest::FromHubParameters(params),
    )? {
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

    // read params
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

    if state.total_bond_statom_amount.u128() > actual_total_bonded.u128() {
        state.total_bond_statom_amount = actual_total_bonded;
    }
    state.update_statom_exchange_rate(state.total_statom_issued);
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
    if is_paused(
        deps.as_ref(),
        env.clone(),
        PausedRequest::FromHubParameters(params),
    )? {
        return Err(StdError::generic_err("the contract is temporarily paused"));
    }

    // call slashing and return new exchange rate
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
        QueryMsg::Parameters {} => to_binary(&query_params(deps, env)?),
        QueryMsg::Guardians { start_after, limit } => {
            to_binary(&query_all_guardians(deps.storage, start_after, limit)?)
        }
    }
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;

    let reward_dispatcher: Option<String> = config.reward_dispatcher_contract.map(|s| s.into());
    let statom_token: Option<String> = config.statom_token_contract.map(|s| s.into());
    let validators_contract: Option<String> = config.validators_registry_contract.map(|s| s.into());

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
        last_processed_batch: state.last_processed_batch,
    };
    Ok(res)
}

fn query_params(deps: Deps, env: Env) -> StdResult<Parameters> {
    let mut params = PARAMETERS.load(deps.storage)?;
    if !is_paused(deps, env, PausedRequest::FromHubParameters(params.clone()))? {
        params.paused_until = None;
    }
    Ok(params)
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

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::new())
}

/// # Description
/// The entry point to the contract for processing the reply from the submessage
/// # Params
/// * **deps** is the object of type [`DepsMut`].
///
/// * **_env** is the object of type [`Env`].
///
/// * **msg** is the object of type [`Reply`].
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> StdResult<Response> {
    if msg.id == TOKENIZE_SHARES_REPLY_ID {
        let recipient = TOKENIZED_SHARE_RECIPIENT.load(deps.storage)?;

        return match msg.result {
            SubMsgResult::Ok(result) => {
                let result_data = match result.data {
                    None => {
                        return Err(StdError::generic_err(
                            "no result data in tokenize share response",
                        ))
                    }
                    Some(data) => data,
                };
                let tokenize_shares_response: MsgTokenizeSharesResponse =
                    match protobuf::Message::parse_from_bytes(result_data.as_slice()) {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(StdError::generic_err(format!(
                                "failed to parse tokenize response from bytes: {}",
                                e
                            )))
                        }
                    };

                let response_coin = match tokenize_shares_response.amount.into_option() {
                    Some(v) => v,
                    None => {
                        return Err(StdError::generic_err(
                            "failed to retrieve coin from tokenize share response",
                        ))
                    }
                };

                let amount = match u128::from_str(response_coin.amount.as_str()) {
                    Ok(a) => a,
                    Err(_) => return Err(StdError::generic_err("failed to parse response amount")),
                };

                Ok(Response::new().add_message(BankMsg::Send {
                    to_address: recipient,
                    amount: [Coin::new(amount, response_coin.denom)].to_vec(),
                }))
            }
            SubMsgResult::Err(err) => Err(StdError::generic_err(format!(
                "tokenize shares failed for {}: {}",
                recipient, err
            ))),
        };
    }

    let res = Response::new();
    Ok(res)
}
