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

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;

use cosmwasm_std::{
    attr, to_binary, Attribute, BankMsg, Binary, Coin, CosmosMsg, Decimal, Deps, DepsMut, Env,
    MessageInfo, Response, StdError, StdResult, Uint128, WasmMsg,
};

use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::state::{Config, CONFIG};
use basset::hub::ExecuteMsg::BondRewards;
use basset::{compute_lido_fee, deduct_tax};
use terra_cosmwasm::{
    create_swap_msg, ExchangeRatesResponse, SwapResponse, TerraMsgWrapper, TerraQuerier,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let conf = Config {
        owner: deps.api.addr_canonicalize(info.sender.as_str())?,
        hub_contract: deps.api.addr_canonicalize(&msg.hub_contract)?,
        stluna_reward_denom: msg.stluna_reward_denom,
        lido_fee_address: deps.api.addr_canonicalize(&msg.lido_fee_address)?,
        lido_fee_rate: msg.lido_fee_rate,
    };

    CONFIG.save(deps.storage, &conf)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response<TerraMsgWrapper>> {
    match msg {
        ExecuteMsg::DispatchRewards {} => execute_dispatch_rewards(deps, env, info),
        ExecuteMsg::UpdateConfig {
            owner,
            hub_contract,
            stluna_reward_denom,
            lido_fee_address,
            lido_fee_rate,
        } => execute_update_config(
            deps,
            env,
            info,
            owner,
            hub_contract,
            stluna_reward_denom,
            lido_fee_address,
            lido_fee_rate,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: Option<String>,
    hub_contract: Option<String>,
    stluna_reward_denom: Option<String>,
    lido_fee_address: Option<String>,
    lido_fee_rate: Option<Decimal>,
) -> StdResult<Response<TerraMsgWrapper>> {
    let conf = CONFIG.load(deps.storage)?;
    let sender_raw = deps.api.addr_canonicalize(info.sender.as_str())?;
    if sender_raw != conf.owner {
        return Err(StdError::generic_err("unauthorized"));
    }

    if let Some(o) = owner {
        let owner_raw = deps.api.addr_canonicalize(&o)?;

        CONFIG.update(deps.storage, |mut last_config| -> StdResult<_> {
            last_config.owner = owner_raw;
            Ok(last_config)
        })?;
    }

    if let Some(h) = hub_contract {
        let hub_raw = deps.api.addr_canonicalize(&h)?;

        CONFIG.update(deps.storage, |mut last_config| -> StdResult<_> {
            last_config.hub_contract = hub_raw;
            Ok(last_config)
        })?;
    }

    if let Some(_s) = stluna_reward_denom {
        return Err(StdError::generic_err(
            "updating stluna reward denom is forbidden",
        ));
    }

    if let Some(r) = lido_fee_rate {
        CONFIG.update(deps.storage, |mut last_config| -> StdResult<_> {
            last_config.lido_fee_rate = r;
            Ok(last_config)
        })?;
    }

    if let Some(a) = lido_fee_address {
        let address_raw = deps.api.addr_canonicalize(&a)?;

        CONFIG.update(deps.storage, |mut last_config| -> StdResult<_> {
            last_config.lido_fee_address = address_raw;
            Ok(last_config)
        })?;
    }

    Ok(Response::default())
}

#[allow(clippy::needless_collect)]
pub(crate) fn convert_to_target_denom(
    deps: &DepsMut,
    balance: Vec<Coin>,
    target_denom: String,
) -> StdResult<(Coin, Vec<CosmosMsg<TerraMsgWrapper>>)> {
    let terra_querier = TerraQuerier::new(&deps.querier);
    let mut total_luna_available: Uint128 = Uint128::zero();

    let denoms: Vec<String> = balance.iter().map(|item| item.denom.clone()).collect();
    let exchange_rates = query_exchange_rates(deps, target_denom.clone(), denoms)?;
    let known_denoms: Vec<String> = exchange_rates
        .exchange_rates
        .iter()
        .map(|item| item.quote_denom.clone())
        .collect();
    let mut msgs: Vec<CosmosMsg<TerraMsgWrapper>> = Vec::new();

    for coin in balance {
        if !known_denoms.contains(&coin.denom) {
            continue;
        }

        if coin.denom == target_denom {
            total_luna_available += coin.amount;
            continue;
        }

        let swap_response: SwapResponse =
            terra_querier.query_swap(coin.clone(), target_denom.as_str())?;
        total_luna_available += swap_response.receive.amount;

        msgs.push(create_swap_msg(coin, target_denom.to_string()));
    }

    Ok((
        Coin {
            amount: total_luna_available,
            denom: target_denom,
        },
        msgs,
    ))
}

pub(crate) fn query_exchange_rates(
    deps: &DepsMut,
    base_denom: String,
    quote_denoms: Vec<String>,
) -> StdResult<ExchangeRatesResponse> {
    let querier = TerraQuerier::new(&deps.querier);
    let res: ExchangeRatesResponse = querier.query_exchange_rates(base_denom, quote_denoms)?;
    Ok(res)
}

pub fn execute_dispatch_rewards(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> StdResult<Response<TerraMsgWrapper>> {
    let config = CONFIG.load(deps.storage)?;

    let hub_addr = deps.api.addr_humanize(&config.hub_contract)?;
    if info.sender != hub_addr {
        return Err(StdError::generic_err("unauthorized"));
    }

    let contr_addr = env.contract.address;
    let balance = deps.querier.query_all_balances(contr_addr)?;
    let (mut stluna_rewards, mut messages) =
        convert_to_target_denom(&deps, balance, config.stluna_reward_denom.clone())?;

    let lido_stluna_fee_amount = compute_lido_fee(stluna_rewards.amount, config.lido_fee_rate)?;
    stluna_rewards.amount = stluna_rewards.amount.checked_sub(lido_stluna_fee_amount)?;

    let mut fees_attrs: Vec<Attribute> = vec![];

    let mut lido_fees: Vec<Coin> = vec![];
    if !lido_stluna_fee_amount.is_zero() {
        let stluna_fee = deduct_tax(
            &deps.querier,
            Coin {
                amount: lido_stluna_fee_amount,
                denom: config.stluna_reward_denom.clone(),
            },
        )?;
        if !stluna_fee.amount.is_zero() {
            lido_fees.push(stluna_fee.clone());
            fees_attrs.push(attr("lido_stluna_fee", stluna_fee.to_string()));
        }
    }

    if !stluna_rewards.amount.is_zero() {
        stluna_rewards = deduct_tax(&deps.querier, stluna_rewards)?;
        messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: hub_addr.to_string(),
            msg: to_binary(&BondRewards {}).unwrap(),
            funds: vec![stluna_rewards.clone()],
        }));
    }
    if !lido_fees.is_empty() {
        messages.push(
            BankMsg::Send {
                to_address: deps
                    .api
                    .addr_humanize(&config.lido_fee_address)?
                    .to_string(),
                amount: lido_fees,
            }
            .into(),
        )
    }

    Ok(Response::new()
        .add_messages(messages)
        .add_attributes(vec![
            attr("action", "claim_reward"),
            attr("stluna_rewards", stluna_rewards.to_string()),
        ])
        .add_attributes(fees_attrs))
}

fn query_config(deps: Deps) -> StdResult<Config> {
    let config = CONFIG.load(deps.storage)?;
    Ok(config)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::GetBufferedRewards {} => unimplemented!(),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: MigrateMsg) -> StdResult<Response> {
    Ok(Response::default())
}
