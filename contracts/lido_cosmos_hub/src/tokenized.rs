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
    attr, to_binary, BalanceResponse, BankQuery, Binary, Coin, CosmosMsg, Decimal, Deps, DepsMut,
    Env, FullDelegation, MessageInfo, QueryRequest, Response, StakingMsg, StakingQuery, StdError,
    StdResult, WasmMsg, WasmQuery,
};

use crate::state::{CONFIG, STATE};
use lido_cosmos_validators_registry::msg::QueryMsg as QueryValidators;

use crate::contract::slashing;
use crate::math::decimal_division;
use crate::tokenize_share_record::{
    QueryTokenizeShareRecordByDenomRequest, QueryTokenizeShareRecordByDenomResponse,
    TokenizeShareRecord,
};
use cw20::Cw20ExecuteMsg;
use lido_cosmos_validators_registry::registry::ValidatorResponse;
use protobuf::Message;
use std::ops::Mul;
use std::string::String;

// no guarantee this actually works, no way to test it yet
// TODO: remove unwraps
fn get_tokenize_share_record_by_denom(
    deps: Deps,
    denom: String,
) -> StdResult<Option<TokenizeShareRecord>> {
    let mut query_data = QueryTokenizeShareRecordByDenomRequest::new();
    query_data.set_denom(denom);

    let response: Binary = deps.querier.query(&QueryRequest::Stargate {
        path: "/liquidstaking.staking.v1beta1.Query/TokenizeShareRecordByDenom".to_string(),
        data: Binary::from(query_data.write_to_bytes().unwrap()),
    })?;

    let decoded_response: QueryTokenizeShareRecordByDenomResponse =
        Message::parse_from_bytes(response.as_slice()).unwrap();

    Ok(decoded_response.record.into_option())
}

struct Voucher {
    amount: Coin,
    tokenize_share_record: TokenizeShareRecord,
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

    let validators_response: Vec<ValidatorResponse> =
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: validators_registry_contract.to_string(),
            msg: to_binary(&QueryValidators::GetValidatorsForDelegation {})?,
        }))?;

    let validators: Vec<String> = validators_response.iter().map(|vr| vr.address).collect();

    // Trying to get TokenizeShareRecord for every voucher we've got by denom.
    // If we can't find a record or we get an error, tx reverted
    //
    // Note: tokenized share denom looks like this:
    // cosmosvaloper1qp49fdjtlsrv6jkx3gc8urp2ncg88s6mcversm12345, where 12345 is the recordId
    // (see https://github.com/iqlusioninc/liquidity-staking-module/blob/master/x/staking/keeper/msg_server.go#L436)
    let vouchers: StdResult<Vec<Voucher>> = info
        .funds
        .into_iter()
        .map(|v| {
            let tokenize_share_response =
                get_tokenize_share_record_by_denom(deps.as_ref(), v.denom.clone());

            // if query fails - return an error
            if tokenize_share_response.is_err() {
                return Err(tokenize_share_response.err().unwrap());
            }

            // if we can't find a record for denom - return an error
            if tokenize_share_response.unwrap().is_none() {
                return Err(StdError::generic_err(format!(
                    "cannot find tokenize share record with denom {}",
                    v.denom.clone()
                )));
            }
            let tokenize_share = tokenize_share_response.unwrap().unwrap();

            // if validator if a record is not in our whitelisted set - return an error
            if !validators.contains(&tokenize_share.validator) {
                return Err(StdError::generic_err(format!(
                    "validator of tokenize share {} is not in our whitelisted set",
                    tokenize_share.share_token_denom
                )));
            }

            // everything is ok - return a record
            Ok(Voucher {
                amount: v,
                tokenize_share_record: tokenize_share,
            })
        })
        .collect();

    let res = Response::new().add_attributes(vec![
        attr("action", "bond_rewards"),
        attr("from", info.sender.clone()),
    ]);

    for voucher in vouchers? {
        let mut messages: Vec<CosmosMsg> = vec![];
        // Note: the RedeemTokensForShares message is not implemented yet.
        // TODO: Stargate msg
        messages.push(cosmwasm_std::CosmosMsg::Staking(
            StakingMsg::RedeemTokensForShares {
                delegator_address: env.contract.address.clone(),
                amount: voucher.amount,
            },
        ));

        // Unfortunately, the response for RedeemTokensForShares does not contain any
        // information at all, so we'll need to calculate the returned amount ourselves.

        // We need to get the delegation info. The .amount field contains the amount of
        // tokens that is calculated using the corresponding amount of shares (see
        // https://github.com/CosmWasm/wasmd/blob/master/x/wasm/keeper/query_plugins.go#L397)
        let delegation_response: Option<FullDelegation> =
            deps.querier
                .query(&QueryRequest::Staking(StakingQuery::Delegation {
                    delegator: voucher.tokenize_share_record.module_account,
                    validator: voucher.tokenize_share_record.validator,
                }))?;

        let delegation: FullDelegation = if let Some(d) = delegation_response {
            d
        } else {
            return Err(StdError::generic_err(format!(
                "Failed to find delegation for {}",
                voucher.tokenize_share_record.share_token_denom
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
                denom: voucher.tokenize_share_record.share_token_denom,
            }))?;

        // Check slashing & get the current exchange rate.
        let state = slashing(&mut deps, env.clone())?;

        // This is the amount of atom that the send tokenized coins equal to:
        // (send tokenized coins / total user amount) * atom value of the
        // full delegation.
        let redeemed_tokens = Decimal::from_ratio(
            voucher.amount.amount.clone(),
            user_tokenized_shares_balance.amount.amount + voucher.amount.amount.clone(),
        )
        .mul(delegation.amount.amount);

        // This is the amount of stATOM tokens that should be minted.
        let mint_amount = decimal_division(redeemed_tokens, state.statom_exchange_rate);

        let token_address = config
            .statom_token_contract
            .ok_or_else(|| StdError::generic_err("the token contract must have been registered"))?;
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

        res.add_attributes(vec![
            attr(
                format!("{}_incoming_amount", voucher.amount.denom),
                voucher.amount.amount.clone(),
            ),
            attr("mint_amount", mint_amount),
        ]);
    }

    Ok(Response::new())
}
