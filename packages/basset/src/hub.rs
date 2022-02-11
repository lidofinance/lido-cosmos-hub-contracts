use cosmwasm_std::{
    to_binary, Addr, Coin, Decimal, Deps, QueryRequest, StdResult, Uint128, WasmQuery,
};
use cw20::Cw20ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(PartialEq)]
pub enum BondType {
    StAtom,
    BondRewards,
}

pub type UnbondRequest = Vec<(u64, Uint128)>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub epoch_period: u64,
    pub underlying_coin_denom: String,
    pub unbonding_period: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct State {
    #[serde(skip_serializing, skip_deserializing)]
    pub total_statom_issued: Uint128,

    pub statom_exchange_rate: Decimal,
    pub total_bond_statom_amount: Uint128,
    pub prev_hub_balance: Uint128,
    pub last_unbonded_time: u64,
    pub last_processed_batch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub creator: Addr,
    pub reward_dispatcher_contract: Option<Addr>,
    pub validators_registry_contract: Option<Addr>,
    pub statom_token_contract: Option<Addr>,
}

impl State {
    pub fn update_statom_exchange_rate(&mut self, total_issued: Uint128, requested: Uint128) {
        let actual_supply = total_issued + requested;
        if self.total_bond_statom_amount.is_zero() || actual_supply.is_zero() {
            self.statom_exchange_rate = Decimal::one()
        } else {
            self.statom_exchange_rate =
                Decimal::from_ratio(self.total_bond_statom_amount, actual_supply);
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    ////////////////////
    /// Owner's operations
    ////////////////////

    /// Set the owener
    UpdateConfig {
        owner: Option<String>,
        rewards_dispatcher_contract: Option<String>,
        validators_registry_contract: Option<String>,
        statom_token_contract: Option<String>,
    },

    /// update the parameters that is needed for the contract
    UpdateParams {
        epoch_period: Option<u64>,
        unbonding_period: Option<u64>,
    },

    /// Pauses the contracts. Only the owner or allowed guardians can pause the contracts
    PauseContracts {},

    /// Unpauses the contracts. Only the owner allowed to unpause the contracts
    UnpauseContracts {},

    ////////////////////
    /// User's operations
    ////////////////////

    /// Receives `amount` in underlying coin denom from sender.
    /// Delegate `amount` equally between validators from the registry.
    /// Issue `amount` / exchange_rate for the user.
    BondForStAtom {},

    BondRewards {},

    /// Dispatch Rewards
    DispatchRewards {},

    /// Send back unbonded coin to the user
    WithdrawUnbonded {},

    /// Check whether the slashing has happened or not
    CheckSlashing {},

    ////////////////////
    /// bAsset's operations
    ///////////////////

    /// Receive interface for send token.
    /// Unbond the underlying coin denom.
    /// Burn the received basset token.
    Receive(Cw20ReceiveMsg),

    ////////////////////
    /// internal operations
    ///////////////////
    RedelegateProxy {
        // delegator is automatically set to address of the calling contract
        src_validator: String,
        redelegations: Vec<(String, Coin)>, //(dst_validator, amount)
    },

    /// Adds a list of addresses to a whitelist of guardians which can pause (but not unpause) the contracts
    AddGuardians {
        addresses: Vec<String>,
    },

    /// Removes a list of a addresses from a whitelist of guardians which can pause (but not unpause) the contracts
    RemoveGuardians {
        addresses: Vec<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Cw20HookMsg {
    Unbond {},
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Parameters {
    pub epoch_period: u64,
    pub underlying_coin_denom: String,
    pub unbonding_period: u64,
    pub paused: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CurrentBatch {
    pub id: u64,
    pub requested_statom: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UnbondHistory {
    pub batch_id: u64,
    pub time: u64,

    pub statom_amount: Uint128,
    pub statom_applied_exchange_rate: Decimal,
    pub statom_withdraw_rate: Decimal,

    pub released: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UnbondHistoryResponse {
    pub batch_id: u64,
    pub time: u64,

    pub statom_amount: Uint128,
    pub statom_applied_exchange_rate: Decimal,
    pub statom_withdraw_rate: Decimal,

    pub released: bool,
}

#[derive(JsonSchema, Serialize, Deserialize, Default)]
pub struct UnbondWaitEntity {
    pub statom_amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct StateResponse {
    pub statom_exchange_rate: Decimal,
    pub total_bond_statom_amount: Uint128,
    pub prev_hub_balance: Uint128,
    pub last_unbonded_time: u64,
    pub last_processed_batch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub owner: String,
    pub reward_dispatcher_contract: Option<String>,
    pub validators_registry_contract: Option<String>,
    pub statom_token_contract: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CurrentBatchResponse {
    pub id: u64,
    pub requested_statom: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WithdrawableUnbondedResponse {
    pub withdrawable: Uint128,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UnbondRequestsResponse {
    pub address: String,
    pub requests: UnbondRequest,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AllHistoryResponse {
    pub history: Vec<UnbondHistoryResponse>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MigrateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
    State {},
    CurrentBatch {},
    WithdrawableUnbonded {
        address: String,
    },
    Parameters {},
    UnbondRequests {
        address: String,
    },
    AllHistory {
        start_from: Option<u64>,
        limit: Option<u32>,
    },
    Guardians,
}

pub fn is_paused(deps: Deps, hub_addr: String) -> StdResult<bool> {
    let params: Parameters = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: hub_addr,
        msg: to_binary(&QueryMsg::Parameters {})?,
    }))?;

    Ok(params.paused.unwrap_or(false))
}
