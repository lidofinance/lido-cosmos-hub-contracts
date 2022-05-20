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

use crate::registry::Validator;
use cosmwasm_std::Uint128;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub registry: Vec<Validator>,
    pub hub_contract: String,
    pub zone: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    //Apply for inclusion in the community registry
    ApplicationRequest {
        address: String,
    },

    ProcessApplications {},

    //Move validator from permission-less list to permissioned list and update weight
    PromoteValidator {
        address: String,
        weight: Uint128,
    },

    //Check validator params and kick validator if needed
    KickValidator {
        address: String,
    },

    /// Update config
    UpdateConfig {
        owner: Option<String>,
        hub_contract: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetValidatorsForDelegation returns validators sorted by available amount for delegation (delegation_limit - total_delegated)
    GetValidatorsForDelegation {},
    Config {},
    HasValidator { address: String },
    GetLargestValidator {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MigrateMsg {}
