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

use crate::registry::ValidatorResponse as RegistryValidator;
use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{
    from_slice, to_binary, Coin, ContractResult, CustomQuery, FullDelegation, OwnedDeps, Querier,
    QuerierResult, QueryRequest, SystemError, Uint128, Validator, WasmQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;

pub const MOCK_CONTRACT_ADDR: &str = "cosmos2contract";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct CustomQueryWrapper {}

// implement custom query
impl CustomQuery for CustomQueryWrapper {}

pub fn mock_dependencies(
    contract_balance: &[Coin],
) -> OwnedDeps<MockStorage, MockApi, WasmMockQuerier> {
    let contract_addr = MOCK_CONTRACT_ADDR;
    let custom_querier: WasmMockQuerier =
        WasmMockQuerier::new(MockQuerier::new(&[(contract_addr, contract_balance)]));

    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: custom_querier,
        custom_query_type: PhantomData,
    }
}

pub struct WasmMockQuerier {
    base: MockQuerier<CustomQueryWrapper>,
    validators: Vec<RegistryValidator>,
}

impl Querier for WasmMockQuerier {
    fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
        // MockQuerier doesn't support Custom, so we ignore it completely here
        let request: QueryRequest<CustomQueryWrapper> = match from_slice(bin_request) {
            Ok(v) => v,
            Err(e) => {
                return QuerierResult::Err(SystemError::InvalidRequest {
                    error: format!("Parsing query request: {}", e),
                    request: bin_request.into(),
                })
            }
        };
        self.handle_query(&request)
    }
}

impl WasmMockQuerier {
    pub fn handle_query(&self, request: &QueryRequest<CustomQueryWrapper>) -> QuerierResult {
        match &request {
            QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: _,
                msg: _,
            }) => {
                let mut validators = self.validators.clone();
                validators.sort_by(|v1, v2| v1.total_delegated.cmp(&v2.total_delegated));
                QuerierResult::Ok(ContractResult::from(to_binary(&validators)))
            }
            _ => self.base.handle_query(request),
        }
    }
    pub fn update_staking(
        &mut self,
        denom: &str,
        validators: &[Validator],
        delegations: &[FullDelegation],
    ) {
        self.base.update_staking(denom, validators, delegations);
    }
}

#[derive(Clone, Default)]
pub struct BalanceQuerier {
    _balances: HashMap<String, Coin>,
}

#[derive(Clone, Default)]
pub struct TokenQuerier {
    _balances: HashMap<String, HashMap<String, Uint128>>,
}

impl WasmMockQuerier {
    pub fn new(base: MockQuerier<CustomQueryWrapper>) -> Self {
        WasmMockQuerier {
            base,
            validators: vec![],
        }
    }
}
