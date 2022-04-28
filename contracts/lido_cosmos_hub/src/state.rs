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

use cosmwasm_std::{Order, StdResult, Storage};
use cw_storage_plus::{Bound, Item, Map};

use basset::hub::{Config, Parameters, State};

pub const CONFIG: Item<Config> = Item::new("config");
pub const PARAMETERS: Item<Parameters> = Item::new("parameters");
pub const STATE: Item<State> = Item::new("state");

// Contains whitelisted address which are allowed to pause (but not unpause) the contracts
pub const GUARDIANS: Map<String, bool> = Map::new("guardians");

/// ## Description
/// Stores addr of recipient who should get converted tokens and address of converted tokens contract
pub const TOKENIZED_SHARE_RECIPIENT: Item<String> = Item::new("tokenized_share_recipient");

// settings for pagination
const MAX_LIMIT: u32 = 100;
const DEFAULT_LIMIT: u32 = 10;

pub fn query_all_guardians(
    storage: &dyn Storage,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Vec<String>> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start = start_after.map(Bound::exclusive);

    let guardians: Result<Vec<_>, _> = GUARDIANS
        .keys(storage, start, None, Order::Ascending)
        .take(limit)
        .collect();

    guardians
}
