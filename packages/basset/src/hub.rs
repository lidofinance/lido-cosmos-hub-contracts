use cosmwasm_std::{CanonicalAddr, Coin, Decimal, Uint128};
use cw20::Cw20ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(PartialEq)]
pub enum BondType {
    StLuna,
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
    pub stluna_exchange_rate: Decimal,
    pub total_bond_stluna_amount: Uint128,
    pub prev_hub_balance: Uint128,
    pub last_unbonded_time: u64,
    pub last_processed_batch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub creator: CanonicalAddr,
    pub reward_dispatcher_contract: Option<CanonicalAddr>,
    pub validators_registry_contract: Option<CanonicalAddr>,
    pub stluna_token_contract: Option<CanonicalAddr>,
}

impl State {
    pub fn update_stluna_exchange_rate(&mut self, total_issued: Uint128, requested: Uint128) {
        let actual_supply = total_issued + requested;
        if self.total_bond_stluna_amount.is_zero() || actual_supply.is_zero() {
            self.stluna_exchange_rate = Decimal::one()
        } else {
            self.stluna_exchange_rate =
                Decimal::from_ratio(self.total_bond_stluna_amount, actual_supply);
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
        stluna_token_contract: Option<String>,
    },

    /// update the parameters that is needed for the contract
    UpdateParams {
        epoch_period: Option<u64>,
        unbonding_period: Option<u64>,
        paused: Option<bool>,
    },

    ////////////////////
    /// User's operations
    ////////////////////

    /// Receives `amount` in underlying coin denom from sender.
    /// Delegate `amount` equally between validators from the registry.
    /// Issue `amount` / exchange_rate for the user.
    BondForStLuna {},

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
    pub requested_stluna: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UnbondHistory {
    pub batch_id: u64,
    pub time: u64,

    pub stluna_amount: Uint128,
    pub stluna_applied_exchange_rate: Decimal,
    pub stluna_withdraw_rate: Decimal,

    pub released: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct UnbondHistoryResponse {
    pub batch_id: u64,
    pub time: u64,

    pub stluna_amount: Uint128,
    pub stluna_applied_exchange_rate: Decimal,
    pub stluna_withdraw_rate: Decimal,

    pub released: bool,
}

#[derive(JsonSchema, Serialize, Deserialize, Default)]
pub struct UnbondWaitEntity {
    pub stluna_amount: Uint128,
}

pub enum UnbondType {
    StLuna,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct StateResponse {
    pub stluna_exchange_rate: Decimal,
    pub total_bond_stluna_amount: Uint128,
    pub prev_hub_balance: Uint128,
    pub last_unbonded_time: u64,
    pub last_processed_batch: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub owner: String,
    pub reward_dispatcher_contract: Option<String>,
    pub validators_registry_contract: Option<String>,
    pub stluna_token_contract: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CurrentBatchResponse {
    pub id: u64,
    pub requested_stluna: Uint128,
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
pub struct MigrateMsg {
    pub reward_dispatcher_contract: String,
    pub validators_registry_contract: String,
    pub stluna_token_contract: String,
}

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
}
