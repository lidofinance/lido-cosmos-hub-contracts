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

use cosmwasm_bignumber::{Decimal256, Uint256};
use cosmwasm_std::{from_slice, to_vec, Decimal, Order, StdError, StdResult, Storage, Uint128};
use cosmwasm_storage::{Bucket, PrefixedStorage, ReadonlyBucket, ReadonlyPrefixedStorage};

use cw_storage_plus::{Item, Map};

use basset::hub::{
    Config, CurrentBatch, Parameters, State, UnbondHistory, UnbondRequest, UnbondWaitEntity,
};
use signed_integer::SignedInt;

pub const CONFIG: Item<Config> = Item::new("config");
pub const PARAMETERS: Item<Parameters> = Item::new("parameters");
pub const CURRENT_BATCH: Item<CurrentBatch> = Item::new("current_batch");
pub const STATE: Item<State> = Item::new("state");

// Contains whitelisted address which are allowed to pause (but not unpause) the contracts
pub const GUARDIANS: Map<String, bool> = Map::new("guardians");

pub static PREFIX_WAIT_MAP: &[u8] = b"wait";
pub static UNBOND_HISTORY_MAP: &[u8] = b"history_map";

pub const MAX_DEFAULT_RANGE_LIMIT: u32 = 1000;

/// Store undelegation wait list per each batch
/// HashMap<user's address, <batch_id, requested_amount>
pub fn store_unbond_wait_list(
    storage: &mut dyn Storage,
    batch_id: u64,
    sender_address: String,
    amount: Uint128,
) -> StdResult<()> {
    let batch = to_vec(&batch_id)?;
    let addr = to_vec(&sender_address)?;
    let mut position_indexer: Bucket<UnbondWaitEntity> =
        Bucket::multilevel(storage, &[PREFIX_WAIT_MAP, &addr]);
    position_indexer.update(&batch, |asked_already| -> StdResult<UnbondWaitEntity> {
        let mut wl = asked_already.unwrap_or_default();
        wl.statom_amount += amount;
        Ok(wl)
    })?;

    Ok(())
}

/// Remove unbond batch id from user's wait list
pub fn remove_unbond_wait_list(
    storage: &mut dyn Storage,
    batch_id: Vec<u64>,
    sender_address: String,
) -> StdResult<()> {
    let addr = to_vec(&sender_address)?;
    let mut position_indexer: Bucket<UnbondWaitEntity> =
        Bucket::multilevel(storage, &[PREFIX_WAIT_MAP, &addr]);
    for b in batch_id {
        let batch = to_vec(&b)?;
        position_indexer.remove(&batch);
    }
    Ok(())
}

pub fn read_unbond_wait_list(
    storage: &dyn Storage,
    batch_id: u64,
    sender_addr: String,
) -> StdResult<UnbondWaitEntity> {
    let vec = to_vec(&sender_addr)?;
    let res: ReadonlyBucket<UnbondWaitEntity> =
        ReadonlyBucket::multilevel(storage, &[PREFIX_WAIT_MAP, &vec]);
    let batch = to_vec(&batch_id)?;
    let wl = res.load(&batch)?;
    Ok(wl)
}

pub fn get_unbond_requests(storage: &dyn Storage, sender_addr: String) -> StdResult<UnbondRequest> {
    let vec = to_vec(&sender_addr)?;
    let mut requests: UnbondRequest = vec![];
    let res: ReadonlyBucket<UnbondWaitEntity> =
        ReadonlyBucket::multilevel(storage, &[PREFIX_WAIT_MAP, &vec]);
    for item in res.range(None, None, Order::Ascending) {
        let (k, value) = item?;
        let user_batch: u64 = from_slice(&k)?;
        requests.push((user_batch, value.statom_amount))
    }
    Ok(requests)
}

pub fn calculate_newly_added_unbonded_amount(
    storage: &dyn Storage,
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
        let statom_historical_rate = Decimal256::from(history.statom_withdraw_rate);
        let statom_unbonded_amount = statom_burnt_amount * statom_historical_rate;

        statom_total_unbonded_amount += statom_unbonded_amount;
        batch_count += 1;
        i += 1;
    }

    (statom_total_unbonded_amount, batch_count)
}

pub fn calculate_new_withdraw_rate(
    amount: Uint128,
    withdraw_rate: Decimal,
    total_unbonded_amount: Uint256,
    slashed_amount: SignedInt,
) -> Decimal {
    let burnt_amount_of_batch = Uint256::from(amount);
    let historical_rate_of_batch = Decimal256::from(withdraw_rate);
    let unbonded_amount_of_batch = burnt_amount_of_batch * historical_rate_of_batch;

    // the slashed amount for each batch must be proportional to the unbonded amount of batch
    let batch_slashing_weight = if total_unbonded_amount != Uint256::zero() {
        Decimal256::from_ratio(unbonded_amount_of_batch.0, total_unbonded_amount.0)
    } else {
        Decimal256::zero()
    };

    let mut slashed_amount_of_batch = batch_slashing_weight * Uint256::from(slashed_amount.0);

    let actual_unbonded_amount_of_batch: Uint256;

    // If slashed amount is negative, there should be summation instead of subtraction.
    if slashed_amount.1 {
        slashed_amount_of_batch = if slashed_amount_of_batch > Uint256::one() {
            slashed_amount_of_batch - Uint256::one()
        } else {
            Uint256::zero()
        };
        actual_unbonded_amount_of_batch = unbonded_amount_of_batch + slashed_amount_of_batch;
    } else {
        if slashed_amount.0.u128() != 0u128 {
            slashed_amount_of_batch += Uint256::one();
        }
        actual_unbonded_amount_of_batch = if slashed_amount_of_batch >= unbonded_amount_of_batch {
            Uint256::zero()
        } else {
            Uint256::from(
                SignedInt::from_subtraction(unbonded_amount_of_batch, slashed_amount_of_batch).0,
            )
        };
    }

    // Calculate the new withdraw rate
    if burnt_amount_of_batch != Uint256::zero() {
        Decimal::from_ratio(actual_unbonded_amount_of_batch, burnt_amount_of_batch)
    } else {
        withdraw_rate
    }
}

/// Return all requested unbond amount.
/// This needs to be called after process withdraw rate function.
/// If the batch is released, this will return user's requested
/// amount proportional to withdraw rate.
pub fn get_finished_amount(
    storage: &dyn Storage,
    sender_addr: String,
) -> StdResult<(Uint128, Vec<u64>)> {
    let vec = to_vec(&sender_addr)?;
    let mut withdrawable_amount: Uint128 = Uint128::zero();
    let mut deprecated_batches: Vec<u64> = vec![];
    let res: ReadonlyBucket<UnbondWaitEntity> =
        ReadonlyBucket::multilevel(storage, &[PREFIX_WAIT_MAP, &vec]);
    for item in res.range(None, None, Order::Ascending) {
        let (k, v) = item?;
        let user_batch: u64 = from_slice(&k)?;
        let history = read_unbond_history(storage, user_batch);
        if let Ok(h) = history {
            if h.released {
                withdrawable_amount += v.statom_amount * h.statom_withdraw_rate;
                deprecated_batches.push(user_batch);
            }
        }
    }
    Ok((withdrawable_amount, deprecated_batches))
}

/// Return the finished amount for all batches that has been before the given block time.
pub fn query_get_finished_amount(
    storage: &dyn Storage,
    sender_addr: String,
    block_time: u64,
    hub_balance: Uint128,
) -> StdResult<Uint128> {
    let state = STATE.load(storage)?;

    let last_processed_batch = state.last_processed_batch;
    let (statom_total_unbonded_amount, batch_count) =
        calculate_newly_added_unbonded_amount(storage, last_processed_batch, block_time);

    if batch_count == 0 {
        return Ok(Uint128::zero());
    }
    let balance_change = SignedInt::from_subtraction(hub_balance, state.prev_hub_balance);
    let actual_unbonded_amount = balance_change.0;
    let statom_slashed_amount = SignedInt::from_subtraction(
        statom_total_unbonded_amount,
        Uint256::from(actual_unbonded_amount),
    );

    let vec = to_vec(&sender_addr)?;
    let mut withdrawable_amount: Uint128 = Uint128::zero();
    let res: ReadonlyBucket<UnbondWaitEntity> =
        ReadonlyBucket::multilevel(storage, &[PREFIX_WAIT_MAP, &vec]);
    for item in res.range(None, None, Order::Ascending) {
        let (k, v) = item?;
        let user_batch: u64 = from_slice(&k)?;
        let history = read_unbond_history(storage, user_batch);
        if let Ok(h) = history {
            if h.time < block_time {
                let new_widrawal_rate = calculate_new_withdraw_rate(
                    h.statom_amount,
                    h.statom_withdraw_rate,
                    statom_total_unbonded_amount,
                    statom_slashed_amount,
                );
                withdrawable_amount += v.statom_amount * new_widrawal_rate;
            }
        }
    }
    Ok(withdrawable_amount)
}

/// Store unbond history map
/// Hashmap<batch_id, <UnbondHistory>>
pub fn store_unbond_history(
    storage: &mut dyn Storage,
    batch_id: u64,
    history: UnbondHistory,
) -> StdResult<()> {
    let vec = batch_id.to_be_bytes().to_vec();
    let value: Vec<u8> = to_vec(&history)?;
    PrefixedStorage::new(storage, UNBOND_HISTORY_MAP).set(&vec, &value);
    Ok(())
}

#[allow(clippy::needless_lifetimes)]
pub fn read_unbond_history(storage: &dyn Storage, epoch_id: u64) -> StdResult<UnbondHistory> {
    let vec = epoch_id.to_be_bytes().to_vec();
    let res = ReadonlyPrefixedStorage::new(storage, UNBOND_HISTORY_MAP).get(&vec);
    match res {
        Some(data) => from_slice(&data),
        None => Err(StdError::generic_err(
            "Burn requests not found for the specified time period",
        )),
    }
}

// settings for pagination
const MAX_LIMIT: u32 = 100;
const DEFAULT_LIMIT: u32 = 10;

/// Return all unbond_history from UnbondHistory map
#[allow(clippy::needless_lifetimes)]
pub fn all_unbond_history(
    storage: &dyn Storage,
    start: Option<u64>,
    limit: Option<u32>,
) -> StdResult<Vec<UnbondHistory>> {
    let vec = convert(start);

    let lim = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let res: StdResult<Vec<UnbondHistory>> =
        ReadonlyPrefixedStorage::new(storage, UNBOND_HISTORY_MAP)
            .range(vec.as_deref(), None, Order::Ascending)
            .take(lim)
            .map(|item| {
                let history: StdResult<UnbondHistory> = from_slice(&item.1);
                history
            })
            .collect();
    res
}

fn convert(start_after: Option<u64>) -> Option<Vec<u8>> {
    start_after.map(|idx| {
        let mut v = idx.to_be_bytes().to_vec();
        v.push(1);
        v
    })
}
