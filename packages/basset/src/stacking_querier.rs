use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Coin, CustomQuery, Decimal, QuerierWrapper, StdResult, Uint128};

/// TerraRoute is enum type to represent terra query route path
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerraRoute {
    Staking,
}

/// TerraQueryWrapper is an override of QueryRequest::Custom to access Terra-specific modules
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct TerraQueryWrapper {
    pub route: TerraRoute,
    pub query_data: TerraQuery,
}

// implement custom query
impl CustomQuery for TerraQueryWrapper {}

/// TerraQuery is defines available query datas
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerraQuery {
    Parameters {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ParametersResponse {
    pub unbonding_time: String,
    pub max_validators: u64,
    pub max_entries: u64,
    pub historical_entries: u64,
    pub bond_denom: String,
}

pub fn get_stacking_params(querier: &QuerierWrapper) -> StdResult<ParametersResponse> {
    let request = TerraQueryWrapper {
        route: TerraRoute::Staking,
        query_data: TerraQuery::Parameters {},
    }
    .into();

    let r = querier.custom_query(&request);
    r
}
