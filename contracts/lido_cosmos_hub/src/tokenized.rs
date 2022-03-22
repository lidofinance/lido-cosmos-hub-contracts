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

use cosmwasm_std::{
    attr, to_binary, Attribute, BalanceResponse, BankQuery, Binary, Coin, CosmosMsg, Decimal, Deps,
    DepsMut, Env, FullDelegation, MessageInfo, QueryRequest, Response, StakingQuery, StdError,
    StdResult, Uint128, WasmMsg, WasmQuery,
};

use crate::state::{CONFIG, PARAMETERS, STATE};
use lido_cosmos_validators_registry::msg::QueryMsg as QueryValidators;

use crate::contract::slashing;
use crate::math::decimal_division;
use crate::tokenize_share_record::{
    Coin as ProtoCoin, MsgRedeemTokensforShares, MsgTokenizeShares,
    QueryTokenizeShareRecordByDenomRequest, QueryTokenizeShareRecordByDenomResponse,
    TokenizeShareRecord,
};
use basset::hub::Parameters;
use cw20::Cw20ExecuteMsg;
use lido_cosmos_validators_registry::registry::ValidatorResponse;
use protobuf::Message;
use std::ops::Mul;
use std::string::String;

use lido_cosmos_validators_registry::registry::ValidatorResponse;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const TOKENIZE_SHARE_RECORD_BY_DENOM_PATH: &str =
    "/liquidstaking.staking.v1beta1.Query/TokenizeShareRecordByDenom";
pub const TOKENIZE_SHARE_RECORD_REDEEM_MSG_TYPE_URL: &str =
    "/liquidstaking.staking.v1beta1.Msg/RedeemTokens";

pub const TOKENIZE_SHARES_PATH: &str = "/liquidstaking.staking.v1beta1.Msg/TokenizeShares";

// no guarantee this actually works, no way to test it yet
// TODO: remove unwraps
fn get_tokenize_share_record_by_denom(
    deps: Deps,
    denom: String,
) -> StdResult<Option<TokenizeShareRecord>> {
    let mut query_data = QueryTokenizeShareRecordByDenomRequest::new();
    query_data.set_denom(denom);

    let response: Binary = deps.querier.query(&QueryRequest::Stargate {
        path: TOKENIZE_SHARE_RECORD_BY_DENOM_PATH.to_string(),
        data: Binary::from(query_data.write_to_bytes().unwrap()),
    })?;

    let decoded_response: QueryTokenizeShareRecordByDenomResponse =
        Message::parse_from_bytes(response.as_slice()).unwrap();

    Ok(decoded_response.record.into_option())
}

// TODO: remove unwraps
pub fn build_redeem_tokenize_share_msg(delegator: String, coin: Coin) -> CosmosMsg {
    let mut proto_coin = ProtoCoin::new();
    proto_coin.set_amount(coin.amount.to_string());
    proto_coin.set_denom(coin.denom);

    let mut redeem_msg = MsgRedeemTokensforShares::new();
    redeem_msg.set_amount(proto_coin);
    redeem_msg.set_delegator_address(delegator);

    let encoded_redeem_msg = Binary::from(redeem_msg.write_to_bytes().unwrap());

    cosmwasm_std::CosmosMsg::Stargate {
        type_url: TOKENIZE_SHARE_RECORD_REDEEM_MSG_TYPE_URL.to_string(),
        value: encoded_redeem_msg,
    }
}

pub fn build_tokenize_share_msg(
    delegator: String,
    validator: String,
    tokenized_share_owner: String,
    coin: Coin,
) -> CosmosMsg {
    let mut proto_coin = ProtoCoin::new();
    proto_coin.set_amount(coin.amount.to_string());
    proto_coin.set_denom(coin.denom);

    let mut tokenize_msg = MsgTokenizeShares::new();
    tokenize_msg.set_amount(proto_coin);
    tokenize_msg.set_validator_address(validator);
    tokenize_msg.set_delegator_address(delegator);
    tokenize_msg.set_tokenized_share_owner(tokenized_share_owner);

    let encoded_tokenize_msg = Binary::from(tokenize_msg.write_to_bytes().unwrap());

    cosmwasm_std::CosmosMsg::Stargate {
        type_url: TOKENIZE_SHARES_PATH.to_string(),
        value: encoded_tokenize_msg,
    }
}

// TODO: query a validators list once and call .has() method
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

// Need to create this struct by myself, because we it's defined as importable in the lib
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DelegationResponse {
    pub delegation: Option<FullDelegation>,
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

// TODO: remove unwraps
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

    let validators_response: Vec<ValidatorResponse> =
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: validators_registry_contract.to_string(),
            msg: to_binary(&QueryValidators::GetValidatorsForDelegation {})?,
        }))?;

    #[allow(clippy::needless_collect)]
    let validators_addresses: Vec<String> = validators_response
        .iter()
        .map(|v| v.address.clone())
        .collect();

    let token_address = config
        .statom_token_contract
        .ok_or_else(|| StdError::generic_err("the token contract must have been registered"))?;

    let mut messages: Vec<CosmosMsg> = vec![];
    let mut attrs: Vec<Attribute> = vec![];

    // Trying to get TokenizeShareRecord for every voucher we've got by denom.
    // If we can't find a record or we get an error, tx reverted
    //
    // Note: tokenized share denom looks like this:
    // cosmosvaloper1qp49fdjtlsrv6jkx3gc8urp2ncg88s6mcversm12345, where 12345 is the recordId
    // (see https://github.com/iqlusioninc/liquidity-staking-module/blob/master/x/staking/keeper/msg_server.go#L436)
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

        if !validators_addresses.contains(&tokenize_share.validator) {
            return Err(StdError::generic_err("Validator is not whitelisted"));
        }

        // Note: the RedeemTokensForShares message is not implemented yet, so we use Stargate feature
        messages.push(build_redeem_tokenize_share_msg(
            env.contract.address.to_string(),
            fund.clone(),
        ));

        // Unfortunately, the response for RedeemTokensForShares does not contain any
        // information at all, so we'll need to calculate the returned amount ourselves.

        // We need to get the delegation info. The .amount field contains the amount of
        // tokens that is calculated using the corresponding amount of shares (see
        // https://github.com/CosmWasm/wasmd/blob/master/x/wasm/keeper/query_plugins.go#L397)
        let delegation_response: DelegationResponse =
            deps.querier
                .query(&QueryRequest::Staking(StakingQuery::Delegation {
                    delegator: tokenize_share.module_account,
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

        // Now we have access to the .amount field, which tells us the **total** amount of
        // tokens that can be currently redeemed. There is no guarantee, though, that the
        // user sends us the full amount of tokenized shares, so we need to understand which
        // fraction of the **total** amount we are redeeming: this can be calculated as
        // the ratio of the sent amount to the user's total balance of the tokenized denom.

        let user_tokenized_shares_balance: BalanceResponse =
            deps.querier.query(&QueryRequest::Bank(BankQuery::Balance {
                address: info.sender.to_string(),
                denom: tokenize_share.share_token_denom,
            }))?;

        // Check slashing & get the current exchange rate.
        let state = slashing(&mut deps, env.clone())?;

        // This is the amount of atom that the send tokenized coins equal to:
        // (send tokenized coins / total user amount) * atom value of the
        // full delegation.
        let redeemed_tokens = Decimal::from_ratio(
            fund.amount,
            user_tokenized_shares_balance.amount.amount + fund.amount,
        )
        .mul(delegation.amount.amount);

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

/// This message must be call by receive_cw20
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

    let max_burn_ratio = if let Some(mbr) = params.max_burn_ratio {
        mbr
    } else {
        return Err(StdError::generic_err("Max burn ratio parameter is empty"));
    };

    if amount > validator.total_delegated.mul(max_burn_ratio) {
        return Err(StdError::generic_err(format!(
            "Can not burn more than {} of the top validator's stake",
            max_burn_ratio
        )));
    }

    messages.push(build_tokenize_share_msg(
        env.contract.address.to_string(),
        validator.address,
        sender.clone(),
        Coin::new(undelegation_amount.u128(), params.underlying_coin_denom),
    ));

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
