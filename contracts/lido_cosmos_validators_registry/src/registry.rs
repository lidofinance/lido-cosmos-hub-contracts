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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Addr;
use cosmwasm_std::Uint128;
use cw_storage_plus::{Item, Map};

pub static CONFIG: Item<Config> = Item::new("config");

pub static REGISTRY: Map<&[u8], Validator> = Map::new("validators_registry");
pub static COMMUNITY_REGISTRY: Map<&[u8], Validator> = Map::new("validators_community_registry");
pub static PENDING_REGISTRY: Map<&[u8], Validator> = Map::new("pending_registry");
pub static VALIDATOR_PARAMS: Map<&[u8], ValidatorParams> = Map::new("validator_params");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub hub_contract: Addr,
    pub zone: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Validator {
    pub address: String,
    pub weight: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ValidatorParams {
    pub last_update: u64,
    pub missed_blocks: u64,        //from last update
    pub signed_blocks_percent: u8, //for last 100 000 blocks
    pub signed_blocks_count: u64,  //for 6 hours
    pub oracle_votes_percent: u8,  //for month
    pub oracle_votes_count: u8,    //for month
    pub oracle_votes: u8,
    pub missed_governance_votes: bool,
    pub missed_network_update: bool,
    pub comission_rate: u8,
    pub jailed: bool,
    pub tombstoned: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ValidatorResponse {
    #[serde(default)]
    pub total_delegated: Uint128,

    pub address: String,
}
