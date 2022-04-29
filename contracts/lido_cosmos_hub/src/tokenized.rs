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
use crate::math::decimal_division;
use crate::state::{CONFIG, PARAMETERS, STATE, TOKENIZED_SHARE_RECIPIENT};
use crate::tokenize_share_record::{
    Coin as ProtoCoin, MsgRedeemTokensforShares, MsgTokenizeShares, QuerySupplyOfRequest,
    QuerySupplyOfResponse, QueryTokenizeShareRecordByDenomRequest,
    QueryTokenizeShareRecordByDenomResponse, TokenizeShareRecord,
};
use basset::hub::Parameters;
use cosmwasm_std::{
    attr, to_binary, to_vec, Addr, Attribute, Binary, CanonicalAddr, Coin, ContractResult,
    CosmosMsg, Decimal, Deps, DepsMut, Empty, Env, FullDelegation, MessageInfo, QueryRequest,
    ReplyOn, Response, StakingQuery, StdError, StdResult, SubMsg, SystemResult, Uint128, WasmMsg,
    WasmQuery,
};
use cw20::Cw20ExecuteMsg;
use lido_cosmos_validators_registry::msg::QueryMsg as QueryValidators;
use lido_cosmos_validators_registry::registry::ValidatorResponse;
use protobuf::Message;
use sha2::{Digest, Sha256};
use std::ops::Mul;
use std::string::String;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// Query path constants
pub const TOKENIZE_SHARE_RECORD_BY_DENOM_PATH: &str =
    "/liquidstaking.staking.v1beta1.Query/TokenizeShareRecordByDenom";
pub const TOKENIZE_SHARE_RECORD_REDEEM_MSG_TYPE_URL: &str =
    "/liquidstaking.staking.v1beta1.MsgRedeemTokensforShares";
pub const BANK_SUPPLY_BY_DENOM_PATH: &str = "/cosmos.bank.v1beta1.Query/SupplyOf";

// Tx path constants
pub const TOKENIZE_SHARES_PATH: &str = "/liquidstaking.staking.v1beta1.MsgTokenizeShares";

pub const TOKENIZE_SHARES_REPLY_ID: u64 = 1;
const TOKENIZE_MODULE_CACONICAL_ADDRESS_LENGTH: usize = 20;

// Need to create this struct by myself, because it's not defined as importable in the lib
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DelegationResponse {
    pub delegation: Option<FullDelegation>,
}

fn make_stargate_query<T: Message>(
    deps: Deps,
    path: String,
    encoded_query_data: Vec<u8>,
) -> StdResult<T> {
    let raw = to_vec::<QueryRequest<Empty>>(&QueryRequest::Stargate {
        path,
        data: Binary::from(encoded_query_data),
    })
    .map_err(|serialize_err| {
        StdError::generic_err(format!("Serializing QueryRequest: {}", serialize_err))
    })?;
    match deps.querier.raw_query(&raw) {
        SystemResult::Err(system_err) => {
            return Err(StdError::generic_err(format!(
                "Querier system error: {}",
                system_err
            )))
        }
        SystemResult::Ok(ContractResult::Err(contract_err)) => {
            return Err(StdError::generic_err(format!(
                "Querier contract error: {}",
                contract_err
            )))
        }
        // response(value) is base64 encoded bytes
        SystemResult::Ok(ContractResult::Ok(value)) => Message::parse_from_bytes(value.as_slice())
            .map_err(|e| StdError::generic_err(format!("Protobuf parsing error: {}", e))),
    }
}

fn get_tokenize_share_record_by_denom(
    deps: Deps,
    denom: String,
) -> StdResult<Option<TokenizeShareRecord>> {
    let mut query_data = QueryTokenizeShareRecordByDenomRequest::new();
    query_data.set_denom(denom);

    let encoded_query_data = match query_data.write_to_bytes() {
        Ok(b) => b,
        Err(e) => return Err(StdError::generic_err(e.to_string())),
    };

    let response: QueryTokenizeShareRecordByDenomResponse = make_stargate_query(
        deps,
        TOKENIZE_SHARE_RECORD_BY_DENOM_PATH.to_string(),
        encoded_query_data,
    )?;
    Ok(response.record.into_option())
}

fn get_bank_supply_of(deps: Deps, denom: String) -> StdResult<Option<ProtoCoin>> {
    let mut query_data = QuerySupplyOfRequest::new();
    query_data.set_denom(denom);

    let encoded_query_data = match query_data.write_to_bytes() {
        Ok(b) => b,
        Err(e) => return Err(StdError::generic_err(e.to_string())),
    };

    let response: QuerySupplyOfResponse = make_stargate_query(
        deps,
        BANK_SUPPLY_BY_DENOM_PATH.to_string(),
        encoded_query_data,
    )?;

    Ok(response.amount.into_option())
}

pub fn build_redeem_tokenize_share_msg(delegator: String, coin: Coin) -> StdResult<CosmosMsg> {
    let mut proto_coin = ProtoCoin::new();
    proto_coin.set_amount(coin.amount.to_string());
    proto_coin.set_denom(coin.denom);

    let mut redeem_msg = MsgRedeemTokensforShares::new();
    redeem_msg.set_amount(proto_coin);
    redeem_msg.set_delegator_address(delegator);

    let encoded_msg_bytes = match redeem_msg.write_to_bytes() {
        Ok(b) => b,
        Err(e) => return Err(StdError::generic_err(e.to_string())),
    };
    let encoded_redeem_msg = Binary::from(encoded_msg_bytes);

    Ok(cosmwasm_std::CosmosMsg::Stargate {
        type_url: TOKENIZE_SHARE_RECORD_REDEEM_MSG_TYPE_URL.to_string(),
        value: encoded_redeem_msg,
    })
}

fn is_known_validator(
    deps: Deps,
    validators_registry_contract: Addr,
    validator: String,
) -> StdResult<bool> {
    let is_known_validator: bool = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: validators_registry_contract.to_string(),
        msg: to_binary(&QueryValidators::HasValidator { address: validator })?,
    }))?;

    Ok(is_known_validator)
}

pub fn build_tokenize_share_msg(
    delegator: String,
    validator: String,
    tokenized_share_owner: String,
    coin: Coin,
) -> StdResult<CosmosMsg> {
    let mut proto_coin = ProtoCoin::new();
    proto_coin.set_amount(coin.amount.to_string());
    proto_coin.set_denom(coin.denom);

    let mut tokenize_msg = MsgTokenizeShares::new();
    tokenize_msg.set_amount(proto_coin);
    tokenize_msg.set_validator_address(validator);
    tokenize_msg.set_delegator_address(delegator);
    tokenize_msg.set_tokenized_share_owner(tokenized_share_owner);

    let encoded_msg_bytes = match tokenize_msg.write_to_bytes() {
        Ok(b) => b,
        Err(e) => return Err(StdError::generic_err(e.to_string())),
    };
    let encoded_tokenize_msg = Binary::from(encoded_msg_bytes);

    Ok(cosmwasm_std::CosmosMsg::Stargate {
        type_url: TOKENIZE_SHARES_PATH.to_string(),
        value: encoded_tokenize_msg,
    })
}

fn get_largest_validator(
    deps: Deps,
    validators_registry_contract: Addr,
) -> StdResult<ValidatorResponse> {
    deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: validators_registry_contract.to_string(),
        msg: to_binary(&QueryValidators::GetLargestValidator {})?,
    }))
}

// we follow the way liquidity staking module does
// canonical address of the module_account calculated like sha256 hash of the name truncated to 20 bytes
pub fn get_module_address(deps: Deps, module_name: String) -> StdResult<String> {
    // https://github.com/iqlusioninc/liquidity-staking-module/blob/faf413d4624af0a6fa8aac2c359d1b1b4f6adbc9/x/staking/types/tokenize_share_record.go#L8
    let result = Sha256::digest(module_name.as_bytes());
    // https://github.com/tendermint/tendermint/blob/master/crypto/crypto.go#L19
    let s = result[..TOKENIZE_MODULE_CACONICAL_ADDRESS_LENGTH].to_vec();
    deps.api
        .addr_humanize(&CanonicalAddr(Binary(s)))
        .map(|s| s.to_string())
}

pub fn receive_tokenized_share(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;

    let validators_registry_contract = if let Some(v) = config.validators_registry_contract {
        v
    } else {
        return Err(StdError::generic_err(
            "Validators registry contract address is empty",
        ));
    };

    let token_address = config
        .statom_token_contract
        .ok_or_else(|| StdError::generic_err("the token contract must have been registered"))?;

    let mut messages: Vec<CosmosMsg> = vec![];
    let mut attrs: Vec<Attribute> = vec![];

    // Trying to get TokenizeShareRecord for every voucher we've got by denom.
    // If we can't find a record or we get an error, tx reverted
    for fund in info.funds.into_iter() {
        let tokenize_share = if let Some(t) =
            get_tokenize_share_record_by_denom(deps.as_ref(), fund.denom.clone())?
        {
            t
        } else {
            return Err(StdError::generic_err(format!(
                "cannot find tokenize share record with denom {}",
                fund.denom
            )));
        };

        if !is_known_validator(
            deps.as_ref(),
            validators_registry_contract.clone(),
            tokenize_share.validator.clone(),
        )? {
            return Err(StdError::generic_err("Validator is not whitelisted"));
        }

        // Note: the RedeemTokensForShares message is not implemented yet, so we use Stargate feature
        messages.push(build_redeem_tokenize_share_msg(
            env.contract.address.to_string(),
            fund.clone(),
        )?);

        // Unfortunately, the response for RedeemTokensForShares does not contain any
        // information at all, so we'll need to calculate the returned amount ourselves.

        // We need to get the delegation info. The .amount field contains the amount of
        // tokens that is calculated using the corresponding amount of shares (see
        // https://github.com/CosmWasm/wasmd/blob/master/x/wasm/keeper/query_plugins.go#L397)
        let delegation_response: DelegationResponse =
            deps.querier
                .query(&QueryRequest::Staking(StakingQuery::Delegation {
                    delegator: get_module_address(deps.as_ref(), tokenize_share.module_account)?,
                    validator: tokenize_share.validator,
                }))?;

        let delegation: FullDelegation = if let Some(d) = delegation_response.delegation {
            d
        } else {
            return Err(StdError::generic_err(format!(
                "Failed to find delegation for {}",
                tokenize_share.share_token_denom
            )));
        };

        // There is no guarantee that the user sends us the full amount of tokenized shares, so we
        // need to understand which fraction of the **total** amount we are redeeming.
        let supply_response =
            if let Some(t) = get_bank_supply_of(deps.as_ref(), fund.denom.clone())? {
                t
            } else {
                return Err(StdError::generic_err(format!(
                    "failed to query denom {} supply",
                    fund.denom
                )));
            };
        let supply_amount = Uint128::from_str(supply_response.get_amount())?;

        // This is absolutely impossible, but Decimal::from_ratio simply panics in case
        // of division by zero, so better safe than sorry.
        if supply_amount.is_zero() {
            return Err(StdError::generic_err(format!(
                "received unexpected zero denom {} supply",
                fund.denom
            )));
        }

        // Check slashing & get the current exchange rate.
        let state = slashing(&mut deps, env.clone())?;

        // This is the amount of atom that the sent tokenized coins equal to:
        // (send tokenized coins / total supply amount) * atom value of the
        // full delegation.
        let redeemed_tokens =
            Decimal::from_ratio(fund.amount, supply_amount).mul(delegation.amount.amount);
        // This is the amount of stATOM tokens that should be minted.
        let mint_amount = decimal_division(redeemed_tokens, state.statom_exchange_rate);

        messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token_address.to_string(),
            msg: to_binary(&Cw20ExecuteMsg::Mint {
                recipient: info.sender.to_string(),
                amount: mint_amount,
            })?,
            funds: vec![],
        }));

        // Update the total bond amount.
        STATE.update(deps.storage, |mut prev_state| -> StdResult<_> {
            prev_state.total_bond_statom_amount += redeemed_tokens;
            Ok(prev_state)
        })?;

        attrs.extend(vec![
            attr(format!("{}_incoming_amount", fund.denom), fund.amount),
            attr("mint_amount", mint_amount),
        ]);
    }

    let res = Response::new()
        .add_attributes(vec![attr("action", "bond"), attr("from", info.sender)])
        .add_attributes(attrs)
        .add_messages(messages);

    Ok(res)
}

/// This message must be called by receive_cw20
/// This message will undelegate coin and burn stAtom tokens
pub(crate) fn execute_unbond_statom(
    mut deps: DepsMut,
    env: Env,
    amount: Uint128,
    sender: String,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    let params: Parameters = PARAMETERS.load(deps.storage)?;

    // Check slashing, update state, and calculate the new exchange rate.
    let mut state = slashing(&mut deps, env.clone())?;

    let mut messages: Vec<CosmosMsg> = vec![];

    let undelegation_amount = amount * state.statom_exchange_rate;
    state.total_bond_statom_amount = state
        .total_bond_statom_amount
        .checked_sub(undelegation_amount)?;

    // Pick the largest validator and check that the burn amount is less than 10% of its stake.
    let validators_registry_contract = if let Some(v) = config.validators_registry_contract {
        v
    } else {
        return Err(StdError::generic_err(
            "Validators registry contract address is empty",
        ));
    };

    let validator = get_largest_validator(deps.as_ref(), validators_registry_contract)?;

    let max_amount_to_burn = validator.total_delegated.mul(params.max_burn_ratio);
    if amount > max_amount_to_burn {
        return Err(StdError::generic_err(format!(
            "Can not burn more than {} of the top validator's stake, which is currently {} {}",
            params.max_burn_ratio, max_amount_to_burn, params.underlying_coin_denom
        )));
    }

    let tokenize_msg = build_tokenize_share_msg(
        env.contract.address.to_string(),
        validator.address,
        sender.clone(),
        Coin::new(undelegation_amount.u128(), params.underlying_coin_denom),
    )?;
    let sub_msg = SubMsg {
        id: TOKENIZE_SHARES_REPLY_ID,
        msg: tokenize_msg,
        gas_limit: None,
        reply_on: ReplyOn::Success,
    };
    TOKENIZED_SHARE_RECIPIENT.save(deps.storage, &sender)?;

    // Store state's new exchange rate
    STATE.save(deps.storage, &state)?;

    // Send Burn message to token contract
    let token_address = config
        .statom_token_contract
        .ok_or_else(|| StdError::generic_err("the token contract must have been registered"))?;

    let burn_msg = Cw20ExecuteMsg::Burn { amount };
    messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: token_address.to_string(),
        msg: to_binary(&burn_msg)?,
        funds: vec![],
    }));

    let res = Response::new()
        .add_submessage(sub_msg)
        .add_messages(messages)
        .add_attributes(vec![
            attr("action", "burn"),
            attr("from", sender),
            attr("burnt_amount", amount),
            attr("undelegation_amount", undelegation_amount),
        ]);
    Ok(res)
}
