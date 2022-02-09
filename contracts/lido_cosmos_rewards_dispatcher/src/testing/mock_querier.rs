// Copyright 2021 Lido
//
// Licensedicensed under the Apache License, Version 2.0 (the "License");
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

use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR};
use cosmwasm_std::{
    from_slice, to_binary, Coin, ContractResult, Decimal, OwnedDeps, Querier, QuerierResult,
    QueryRequest, SystemError, Uint128, WasmQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use terra_cosmwasm::{TaxCapResponse, TaxRateResponse, TerraQuery, TerraQueryWrapper, TerraRoute};

pub const MOCK_HUB_CONTRACT_ADDR: &str = "hub";
pub const MOCK_LIDO_FEE_ADDRESS: &str = "lido_fee";

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
    base: MockQuerier<TerraQueryWrapper>,
}

impl Querier for WasmMockQuerier {
    fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
        // MockQuerier doesn't support Custom, so we ignore it completely here
        let request: QueryRequest<TerraQueryWrapper> = match from_slice(bin_request) {
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
    pub fn handle_query(&self, request: &QueryRequest<TerraQueryWrapper>) -> QuerierResult {
        match &request {
            QueryRequest::Custom(TerraQueryWrapper { route, query_data }) => {
                if &TerraRoute::Treasury == route
                    || &TerraRoute::Market == route
                    || &TerraRoute::Oracle == route
                {
                    match query_data {
                        TerraQuery::TaxRate {} => {
                            let res = TaxRateResponse {
                                rate: Decimal::percent(1),
                            };
                            QuerierResult::Ok(ContractResult::from(to_binary(&res)))
                        }
                        TerraQuery::TaxCap { denom: _ } => {
                            let cap = Uint128::from(1000000u128);
                            let res = TaxCapResponse { cap };
                            QuerierResult::Ok(ContractResult::from(to_binary(&res)))
                        }
                        _ => panic!("DO NOT ENTER HERE"),
                    }
                } else {
                    panic!(
                        "UNSUPPORTED ROUTE! ROUTE: {:?}, DATA: {:?}",
                        route, query_data
                    )
                }
            }
            QueryRequest::Wasm(WasmQuery::Raw {
                contract_addr: _,
                key: _,
            }) => unimplemented!(),
            _ => self.base.handle_query(request),
        }
    }
}

impl WasmMockQuerier {
    pub fn new(base: MockQuerier<TerraQueryWrapper>) -> Self {
        WasmMockQuerier { base }
    }
}

/// ExchangeRatesResponse is data format returned from OracleRequest::ExchangeRates query
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ExchangeRatesResponse {
    pub base_denom: String,
    pub exchange_rates: Vec<ExchangeRateItem>,
}

/// ExchangeRateItem is data format returned from OracleRequest::ExchangeRates query
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ExchangeRateItem {
    pub quote_denom: String,
    pub exchange_rate: Decimal,
}
