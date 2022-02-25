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
    attr, to_binary, BalanceResponse, BankQuery, Coin, CosmosMsg, Decimal, DelegationResponse,
    DepsMut, Env, FullDelegation, MessageInfo, QueryRequest, Response, StakingMsg, StakingQuery,
    StdError, StdResult, Uint128, WasmMsg, WasmQuery,
};

use crate::state::{CONFIG, STATE};
use lido_cosmos_validators_registry::msg::QueryMsg as QueryValidators;

use crate::contract::slashing;
use crate::math::decimal_division;
use cw20::Cw20ExecuteMsg;
use std::ops::Mul;

pub fn receive_tokenized_share(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    validator: String,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    // Check that the validator specified in the message is a whitelisted validator.
    {
        let validators_registry_contract = if let Some(v) = config.validators_registry_contract {
            v
        } else {
            return Err(StdError::generic_err(
                "Validators registry contract address is empty",
            ));
        };
        let is_known_validator: bool =
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: validators_registry_contract.to_string(),
                msg: to_binary(&QueryValidators::HasValidator {
                    address: validator.clone(),
                })?,
            }))?;
        if !is_known_validator {
            return Err(StdError::generic_err("Validator is not whitelisted"));
        }
    }

    // Take all tokenized shares of the specified validator's delegations.
    // Note: tokenized share denom looks like this:
    // cosmosvaloper1qp49fdjtlsrv6jkx3gc8urp2ncg88s6mcversm12345, where 12345 is the recordId
    // (see https://github.com/iqlusioninc/liquidity-staking-module/blob/master/x/staking/keeper/msg_server.go#L436)
    let vouchers: Vec<Coin> = info
        .funds
        .into_iter()
        .filter(|x| x.denom.contains(&validator) && x.amount > Uint128::zero())
        .collect();

    let res = Response::new().add_attributes(vec![
        attr("action", "bond_rewards"),
        attr("from", info.sender.clone()),
    ]);
    for voucher in vouchers {
        let mut messages: Vec<CosmosMsg> = vec![];
        // Note: the RedeemTokensForShares message is not implemented yet.
        messages.push(cosmwasm_std::CosmosMsg::Staking(
            StakingMsg::RedeemTokensForShares {
                delegator_address: validator.clone(),
                amount: voucher,
            },
        ));

        // Unfortunately, the response for RedeemTokensForShares does not contain any
        // information at all, so we'll need to calculate the returned amount ourselves.

        // We need to get the tokenized share module account somehow to query for the
        // delegation. The module account is recorded as fmt.Sprintf("tokenizeshare_%d", recordId)
        // during the creation of a share, ad there is no direct way to get tokenizedShareRecord
        // from the liquid staking module, so we'll need to extract it from token denom
        // in a dirty way.
        let delegator = if let Some(acc) = voucher.denom.clone().rsplit(&validator).next() {
            acc
        } else {
            return Err(StdError::generic_err(format!(
                "Failed to get recordId from tokenized share {}",
                voucher.denom.clone()
            )));
        };

        // Now we need to get the delegation info. The .amount field contains the amount of
        // tokens that is calculated using the corresponding amount of shares (see
        // https://github.com/CosmWasm/wasmd/blob/master/x/wasm/keeper/query_plugins.go#L397)
        let delegation_response: DelegationResponse =
            deps.querier
                .query(&QueryRequest::Staking(StakingQuery::Delegation {
                    delegator: delegator.to_string(),
                    validator: validator.clone(),
                }))?;

        let delegation: FullDelegation = if let Some(d) = delegation_response.delegation {
            d
        } else {
            return Err(StdError::generic_err(format!(
                "Failed to find delegation for {}",
                voucher.denom.clone()
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
                denom: voucher.denom.clone(),
            }))?;

        // Check slashing & get the current exchange rate.
        let state = slashing(&mut deps, env.clone())?;

        // This is the amount of atom that the send tokenized coins equal to:
        // (send tokenized coins / total user amount) * atom value of the
        // full delegation.
        let redeemed_tokens = Decimal::from_ratio(
            voucher.amount.clone(),
            user_tokenized_shares_balance.amount.amount,
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
                format!("{}_incoming_amount", voucher.denom.clone()),
                voucher.amount.clone(),
            ),
            attr(
                format!("{}_mint_amount", voucher.denom.clone()),
                mint_amount,
            ),
        ]);
    }

    Ok(Response::new())
}
