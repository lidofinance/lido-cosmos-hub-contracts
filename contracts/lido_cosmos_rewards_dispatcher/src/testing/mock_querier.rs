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

use basset::hub::{Parameters, QueryMsg};
use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR};
use cosmwasm_std::{
    from_slice, to_binary, Coin, ContractResult, CustomQuery, OwnedDeps, Querier, QuerierResult,
    QueryRequest, SystemError, SystemResult, WasmQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MOCK_HUB_CONTRACT_ADDR: &str = "hub";
pub const MOCK_LIDO_FEE_ADDRESS: &str = "lido_fee";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct CustomQueryWrapper {}

// implement custom query
impl CustomQuery for CustomQueryWrapper {}

pub fn mock_dependencies(
    contract_balance: &[Coin],
) -> OwnedDeps<MockStorage, MockApi, WasmMockQuerier> {
    let contract_addr = String::from(MOCK_CONTRACT_ADDR);
    let custom_querier: WasmMockQuerier =
        WasmMockQuerier::new(MockQuerier::new(&[(&contract_addr, contract_balance)]));

    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: custom_querier,
    }
}

pub struct WasmMockQuerier {
    base: MockQuerier<CustomQueryWrapper>,
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
                });
            }
        };
        self.handle_query(&request)
    }
}

impl WasmMockQuerier {
    pub fn handle_query(&self, request: &QueryRequest<CustomQueryWrapper>) -> QuerierResult {
        match &request {
            QueryRequest::Wasm(WasmQuery::Smart { contract_addr, msg }) => {
                if *contract_addr == MOCK_HUB_CONTRACT_ADDR {
                    if msg == &to_binary(&QueryMsg::Parameters {}).unwrap() {
                        let params = Parameters {
                            epoch_period: 0,
                            underlying_coin_denom: "".to_string(),
                            unbonding_period: 0,
                            paused: None,
                        };
                        SystemResult::Ok(ContractResult::from(to_binary(&params)))
                    } else {
                        unimplemented!()
                    }
                } else {
                    unimplemented!()
                }
            }
            _ => self.base.handle_query(request),
        }
    }
}

impl WasmMockQuerier {
    pub fn new(base: MockQuerier<CustomQueryWrapper>) -> Self {
        WasmMockQuerier { base }
    }
}
