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
use crate::contract::slashing;
use crate::state::{
    get_finished_amount, read_unbond_history, remove_unbond_wait_list, store_unbond_history,
    store_unbond_wait_list, CONFIG, CURRENT_BATCH, PARAMETERS, STATE,
};
use basset::hub::{CurrentBatch, State, UnbondHistory};
use std::str::FromStr;
// use cosmwasm_bignumber::{Decimal256, Uint256};
use cosmwasm_std::{
    attr, coin, coins, to_binary, BankMsg, CosmosMsg, Decimal, Decimal256, DepsMut, Env,
    MessageInfo, Response, StakingMsg, StdError, StdResult, Storage, Uint128, Uint256, WasmMsg,
};
use cw20::Cw20ExecuteMsg;
use lido_cosmos_validators_registry::common::calculate_undelegations;
use lido_cosmos_validators_registry::registry::ValidatorResponse;
use signed_integer::SignedInt;

pub fn execute_withdraw_unbonded(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> StdResult<Response> {
    let params = PARAMETERS.load(deps.storage)?;
    if params.paused.unwrap_or(false) {
        return Err(StdError::generic_err("The contract is temporarily paused"));
    }
    let sender_human = info.sender;
    let contract_address = env.contract.address.clone();
    let unbonding_period = params.unbonding_period;
    let coin_denom = params.underlying_coin_denom;

    let historical_time = env.block.time.seconds() - unbonding_period;

    // query hub balance for process withdraw rate.
    let hub_balance = deps
        .querier
        .query_balance(&env.contract.address, &*coin_denom)?
        .amount;

    // calculate withdraw rate for user requests
    process_withdraw_rate(&mut deps, historical_time, hub_balance)?;

    let (withdraw_amount, deprecated_batches) =
        get_finished_amount(deps.storage, sender_human.to_string())?;

    if withdraw_amount.is_zero() {
        return Err(StdError::generic_err(format!(
            "No withdrawable {} assets are available yet",
            coin_denom
        )));
    }

    // remove the previous batches for the user
    remove_unbond_wait_list(deps.storage, deprecated_batches, sender_human.to_string())?;

    // Update previous balance used for calculation in next Atom batch release
    let prev_balance = hub_balance.checked_sub(withdraw_amount)?;
    STATE.update(deps.storage, |mut last_state| -> StdResult<_> {
        last_state.prev_hub_balance = prev_balance;
        Ok(last_state)
    })?;

    // Send the money to the user
    let msgs: Vec<CosmosMsg> = vec![BankMsg::Send {
        to_address: sender_human.to_string(),
        amount: coins(withdraw_amount.u128(), &*coin_denom),
    }
    .into()];

    let res = Response::new().add_messages(msgs).add_attributes(vec![
        attr("action", "finish_burn"),
        attr("from", contract_address),
        attr("amount", withdraw_amount),
    ]);
    Ok(res)
}

fn calculate_newly_added_unbonded_amount(
    storage: &mut dyn Storage,
    last_processed_batch: u64,
    historical_time: u64,
) -> (Uint256, u64) {
    let mut statom_total_unbonded_amount = Uint256::zero();
    let mut batch_count: u64 = 0;

    // Iterate over unbonded histories that have been processed
    // to calculate newly added unbonded amount
    let mut i = last_processed_batch + 1;
    loop {
        let history: UnbondHistory;
        match read_unbond_history(storage, i) {
            Ok(h) => {
                if h.time > historical_time {
                    break;
                }
                if !h.released {
                    history = h.clone();
                } else {
                    break;
                }
            }
            Err(_) => break,
        }
        let statom_burnt_amount = Uint256::from(history.statom_amount);

        // FIX: check the error
        let statom_historical_rate = Decimal256::from_atomics(
            history.statom_withdraw_rate.atomics(),
            history.statom_withdraw_rate.decimal_places(),
        )
        .unwrap();
        let statom_unbonded_amount = statom_burnt_amount * statom_historical_rate;

        statom_total_unbonded_amount += statom_unbonded_amount;
        batch_count += 1;
        i += 1;
    }

    (statom_total_unbonded_amount, batch_count)
}

fn u256_to_u128(f: Uint256) -> Uint128 {
    // FIX: quick dirty hack
    Uint128::from_str(f.to_string().as_str()).unwrap()
}

fn calculate_new_withdraw_rate(
    amount: Uint128,
    withdraw_rate: Decimal,
    total_unbonded_amount: Uint256,
    slashed_amount: SignedInt,
) -> Decimal {
    let burnt_amount_of_batch = Uint256::from(amount);
    let historical_rate_of_batch =
        Decimal256::from_atomics(withdraw_rate.atomics(), withdraw_rate.decimal_places()).unwrap();
    let unbonded_amount_of_batch = burnt_amount_of_batch * historical_rate_of_batch;

    // the slashed amount for each batch must be proportional to the unbonded amount of batch
    let batch_slashing_weight = if total_unbonded_amount != Uint256::zero() {
        Decimal256::from_ratio(unbonded_amount_of_batch, total_unbonded_amount)
    } else {
        Decimal256::zero()
    };

    let mut slashed_amount_of_batch = batch_slashing_weight * Uint256::from(slashed_amount.0);

    let actual_unbonded_amount_of_batch: Uint256;

    // If slashed amount is negative, there should be summation instead of subtraction.
    if slashed_amount.1 {
        slashed_amount_of_batch = if slashed_amount_of_batch > Uint256::from(1u32) {
            slashed_amount_of_batch - Uint256::from(1u32)
        } else {
            Uint256::zero()
        };
        actual_unbonded_amount_of_batch = unbonded_amount_of_batch + slashed_amount_of_batch;
    } else {
        if !slashed_amount.0.is_zero() {
            slashed_amount_of_batch += Uint256::from(1u32);
        }
        actual_unbonded_amount_of_batch = Uint256::from(
            SignedInt::from_subtraction(unbonded_amount_of_batch, slashed_amount_of_batch).0,
        );
    }

    // Calculate the new withdraw rate
    if burnt_amount_of_batch != Uint256::zero() {
        Decimal::from_ratio(u256_to_u128(actual_unbonded_amount_of_batch), u256_to_u128(burnt_amount_of_batch))
    } else {
        withdraw_rate
    }
}

/// This is designed for an accurate unbonded amount calculation.
/// Execute while processing withdraw_unbonded
fn process_withdraw_rate(
    deps: &mut DepsMut,
    historical_time: u64,
    hub_balance: Uint128,
) -> StdResult<()> {
    let mut state = STATE.load(deps.storage)?;

    let last_processed_batch = state.last_processed_batch;

    let (statom_total_unbonded_amount, batch_count) =
        calculate_newly_added_unbonded_amount(deps.storage, last_processed_batch, historical_time);

    if batch_count < 1 {
        return Ok(());
    }

    let balance_change = SignedInt::from_subtraction(hub_balance, state.prev_hub_balance);
    let actual_unbonded_amount = balance_change.0;

    let statom_slashed_amount = SignedInt::from_subtraction(
        statom_total_unbonded_amount,
        Uint256::from(actual_unbonded_amount),
    );

    // Iterate again to calculate the withdraw rate for each unprocessed history
    let mut iterator = last_processed_batch + 1;
    loop {
        let history: UnbondHistory;
        match read_unbond_history(deps.storage, iterator) {
            Ok(h) => {
                if h.time > historical_time {
                    break;
                }
                if !h.released {
                    history = h
                } else {
                    break;
                }
            }
            Err(_) => {
                break;
            }
        }

        // Calculate the new withdraw rate
        let statom_new_withdraw_rate = calculate_new_withdraw_rate(
            history.statom_amount,
            history.statom_withdraw_rate,
            statom_total_unbonded_amount,
            statom_slashed_amount,
        );

        let mut history_for_i = history;
        // store the history and mark it as released
        history_for_i.statom_withdraw_rate = statom_new_withdraw_rate;
        history_for_i.released = true;
        store_unbond_history(deps.storage, iterator, history_for_i)?;
        state.last_processed_batch = iterator;
        iterator += 1;
    }

    STATE.save(deps.storage, &state)?;

    Ok(())
}

fn pick_validator(deps: &DepsMut, claim: Uint128, delegator: String) -> StdResult<Vec<CosmosMsg>> {
    //read params
    let params = PARAMETERS.load(deps.storage)?;
    let coin_denom = params.underlying_coin_denom;

    let mut messages: Vec<CosmosMsg> = vec![];

    let all_delegations = deps.querier.query_all_delegations(delegator)?;

    let mut validators = all_delegations
        .iter()
        .map(|d| ValidatorResponse {
            total_delegated: d.amount.amount,
            address: d.validator.clone(),
        })
        .collect::<Vec<ValidatorResponse>>();
    validators.sort_by(|v1, v2| v2.total_delegated.cmp(&v1.total_delegated));

    let undelegations = calculate_undelegations(claim, validators.clone())?;

    for (index, undelegated_amount) in undelegations.iter().enumerate() {
        if undelegated_amount.is_zero() {
            continue;
        }

        let msgs: CosmosMsg = CosmosMsg::Staking(StakingMsg::Undelegate {
            validator: validators[index].address.clone(),
            amount: coin(undelegated_amount.u128(), &*coin_denom),
        });
        messages.push(msgs);
    }
    Ok(messages)
}

/// This message must be call by receive_cw20
/// This message will undelegate coin and burn stAtom tokens
pub(crate) fn execute_unbond_statom(
    mut deps: DepsMut,
    env: Env,
    amount: Uint128,
    sender: String,
) -> StdResult<Response> {
    // Read params
    let params = PARAMETERS.load(deps.storage)?;
    let epoch_period = params.epoch_period;

    let mut current_batch = CURRENT_BATCH.load(deps.storage)?;

    // Check slashing, update state, and calculate the new exchange rate.
    let mut state = slashing(&mut deps, env.clone())?;

    // Collect all the requests within a epoch period
    current_batch.requested_statom += amount;

    store_unbond_wait_list(deps.storage, current_batch.id, sender.clone(), amount)?;

    let current_time = env.block.time.seconds();
    let passed_time = current_time - state.last_unbonded_time;

    let mut messages: Vec<CosmosMsg> = vec![];

    // If the epoch period is passed, the undelegate message would be sent.
    if passed_time > epoch_period {
        let mut undelegate_msgs =
            process_undelegations(&mut deps, env, &mut current_batch, &mut state)?;
        messages.append(&mut undelegate_msgs);
    }

    // Store the new requested_with_fee or id in the current batch
    CURRENT_BATCH.save(deps.storage, &current_batch)?;

    // Store state's new exchange rate
    STATE.save(deps.storage, &state)?;

    // Send Burn message to token contract
    let config = CONFIG.load(deps.storage)?;
    let token_address = config
        .statom_token_contract
        .ok_or_else(|| StdError::generic_err("the token contract must have been registered"))?;

    let burn_msg = Cw20ExecuteMsg::Burn { amount };
    messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: token_address.to_string(),
        msg: to_binary(&burn_msg)?,
        funds: vec![],
    }));

    let res = Response::new().add_messages(messages).add_attributes(vec![
        attr("action", "burn"),
        attr("from", sender),
        attr("burnt_amount", amount),
        attr("unbonded_amount", amount),
    ]);
    Ok(res)
}

fn process_undelegations(
    deps: &mut DepsMut,
    env: Env,
    current_batch: &mut CurrentBatch,
    state: &mut State,
) -> StdResult<Vec<CosmosMsg>> {
    // Apply the current exchange rate.
    let statom_undelegation_amount = current_batch.requested_statom * state.statom_exchange_rate;
    let delegator = env.contract.address;

    // Send undelegated requests to possibly more than one validators
    let undelegated_msgs = pick_validator(deps, statom_undelegation_amount, delegator.to_string())?;

    state.total_bond_statom_amount = state
        .total_bond_statom_amount
        .checked_sub(statom_undelegation_amount)?;

    // Store history for withdraw unbonded
    let history = UnbondHistory {
        batch_id: current_batch.id,
        time: env.block.time.seconds(),
        statom_amount: current_batch.requested_statom,
        statom_applied_exchange_rate: state.statom_exchange_rate,
        statom_withdraw_rate: state.statom_exchange_rate,

        released: false,
    };

    store_unbond_history(deps.storage, current_batch.id, history)?;
    // batch info must be updated to new batch
    current_batch.id += 1;
    current_batch.requested_statom = Uint128::zero();

    // state.last_unbonded_time must be updated to the current block time
    state.last_unbonded_time = env.block.time.seconds();

    Ok(undelegated_msgs)
}
