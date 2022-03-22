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

use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{
    from_binary, from_slice, to_binary, to_vec, Addr, AllBalanceResponse, Api, BalanceResponse,
    BankQuery, Binary, Coin, ContractResult, CustomQuery, Empty, FullDelegation, OwnedDeps,
    Querier, QuerierResult, QueryRequest, StdError, StdResult, SystemError, SystemResult, Uint128,
    Validator, WasmQuery,
};
use cosmwasm_storage::to_length_prefixed;
use cw20_base::state::{MinterData, TokenInfo};
use lido_cosmos_validators_registry::registry::ValidatorResponse as RegistryValidator;
use std::collections::HashMap;

use crate::tokenize_share_record::{
    QueryTokenizeShareRecordByDenomRequest, QueryTokenizeShareRecordByDenomResponse,
    TokenizeShareRecord,
};
use crate::tokenized::TOKENIZE_SHARE_RECORD_BY_DENOM_PATH;
use basset::hub::Config;
use cw20::{BalanceResponse as Cw20BalanceResponse, Cw20QueryMsg};
use lido_cosmos_validators_registry::msg::QueryMsg as QueryValidators;
use protobuf::Message;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const MOCK_CONTRACT_ADDR: &str = "cosmos2contract";
pub const VALIDATORS_REGISTRY: &str = "validators_registry";

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
    }
}

pub(crate) fn _caps_to_map(caps: &[(&String, &Uint128)]) -> HashMap<String, Uint128> {
    let mut owner_map: HashMap<String, Uint128> = HashMap::new();
    for (denom, cap) in caps.iter() {
        owner_map.insert(denom.to_string(), **cap);
    }
    owner_map
}

pub struct WasmMockQuerier {
    base: MockQuerier<CustomQueryWrapper>,
    token_querier: TokenQuerier,
    balance_querier: BalanceQuerier,
    validators: Vec<RegistryValidator>,
    tokenize_share_records: Vec<TokenizeShareRecord>,
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
            QueryRequest::Stargate { path, data } => {
                if path.as_str() == TOKENIZE_SHARE_RECORD_BY_DENOM_PATH {
                    let request: QueryTokenizeShareRecordByDenomRequest =
                        Message::parse_from_bytes(data.as_slice()).unwrap();
                    let mut response = QueryTokenizeShareRecordByDenomResponse::new();
                    let record = self
                        .tokenize_share_records
                        .iter()
                        .find(|r| r.share_token_denom == request.denom);
                    if record.is_none() {
                        return SystemResult::Ok(ContractResult::from(to_binary(&Binary::from(
                            response.write_to_bytes().unwrap(),
                        ))));
                    }
                    response.set_record(record.unwrap().clone());

                    SystemResult::Ok(ContractResult::from(to_binary(&Binary::from(
                        response.write_to_bytes().unwrap(),
                    ))))
                } else {
                    unimplemented!()
                }
            }
            QueryRequest::Wasm(WasmQuery::Smart { contract_addr, msg }) => {
                if contract_addr == VALIDATORS_REGISTRY {
                    match from_binary(msg).unwrap() {
                        QueryValidators::HasValidator { address } => {
                            return SystemResult::Ok(ContractResult::from(to_binary(
                                &self.validators.iter().any(|v| v.address == address),
                            )))
                        }
                        QueryValidators::GetValidatorsForDelegation {} => {
                            let mut validators = self.validators.clone();
                            validators
                                .sort_by(|v1, v2| v1.total_delegated.cmp(&v2.total_delegated));
                            return SystemResult::Ok(ContractResult::from(to_binary(&validators)));
                        }
                        _ => {
                            unimplemented!()
                        }
                    }
                }
                match from_binary(msg).unwrap() {
                    Cw20QueryMsg::TokenInfo {} => {
                        let balances: &HashMap<String, Uint128> =
                            match self.token_querier.balances.get(contract_addr) {
                                Some(balances) => balances,
                                None => {
                                    return SystemResult::Err(SystemError::InvalidRequest {
                                        error: format!(
                                            "No balance info exists for the contract {}",
                                            contract_addr
                                        ),
                                        request: msg.as_slice().into(),
                                    })
                                }
                            };
                        let mut total_supply = Uint128::zero();

                        for balance in balances {
                            total_supply += *balance.1;
                        }
                        let token_inf: TokenInfo = TokenInfo {
                            name: "statom".to_string(),
                            symbol: "STATOM".to_string(),
                            decimals: 6,
                            total_supply,
                            mint: Some(MinterData {
                                minter: Addr::unchecked(MOCK_CONTRACT_ADDR),
                                cap: None,
                            }),
                        };
                        SystemResult::Ok(ContractResult::Ok(to_binary(&token_inf).unwrap()))
                    }
                    Cw20QueryMsg::Balance { address } => {
                        let balances: &HashMap<String, Uint128> =
                            match self.token_querier.balances.get(contract_addr) {
                                Some(balances) => balances,
                                None => {
                                    return SystemResult::Err(SystemError::InvalidRequest {
                                        error: format!(
                                            "No balance info exists for the contract {}",
                                            contract_addr
                                        ),
                                        request: msg.as_slice().into(),
                                    })
                                }
                            };

                        let balance = match balances.get(&address) {
                            Some(v) => *v,
                            None => {
                                return SystemResult::Ok(ContractResult::Ok(
                                    to_binary(&Cw20BalanceResponse {
                                        balance: Uint128::zero(),
                                    })
                                    .unwrap(),
                                ));
                            }
                        };

                        SystemResult::Ok(ContractResult::Ok(
                            to_binary(&Cw20BalanceResponse { balance }).unwrap(),
                        ))
                    }
                    _ => panic!("DO NOT ENTER HERE"),
                }
            }
            QueryRequest::Wasm(WasmQuery::Raw {
                contract_addr: _,
                key,
            }) => {
                let prefix_config = to_length_prefixed(b"config").to_vec();
                let api: MockApi = MockApi::default();

                if key.as_slice().to_vec() == prefix_config {
                    let config = Config {
                        creator: api.addr_validate(&String::from("owner1")).unwrap(),
                        reward_dispatcher_contract: Some(
                            api.addr_validate(&String::from("reward")).unwrap(),
                        ),
                        validators_registry_contract: Some(
                            api.addr_validate(&String::from("validators")).unwrap(),
                        ),
                        statom_token_contract: Some(
                            api.addr_validate(&String::from("statom_token")).unwrap(),
                        ),
                    };
                    QuerierResult::Ok(ContractResult::from(to_binary(
                        &to_binary(&config).unwrap(),
                    )))
                } else {
                    unimplemented!()
                }
            }
            QueryRequest::Bank(BankQuery::AllBalances { address }) => {
                if address == &String::from("reward") {
                    let mut coins: Vec<Coin> = vec![];
                    let atom = Coin {
                        denom: "uatom".to_string(),
                        amount: Uint128::from(1000u128),
                    };
                    coins.push(atom);
                    let krt = Coin {
                        denom: "ukrt".to_string(),
                        amount: Uint128::from(1000u128),
                    };
                    coins.push(krt);
                    let usd = Coin {
                        denom: "uusd".to_string(),
                        amount: Uint128::from(1000u128),
                    };
                    coins.push(usd);
                    let all_balances = AllBalanceResponse { amount: coins };
                    QuerierResult::Ok(ContractResult::from(to_binary(&all_balances)))
                } else {
                    unimplemented!()
                }
            }
            QueryRequest::Bank(BankQuery::Balance { address, denom }) => {
                if address == &String::from(MOCK_CONTRACT_ADDR) && denom == "uatom" {
                    match self
                        .balance_querier
                        .balances
                        .get(&String::from(MOCK_CONTRACT_ADDR))
                    {
                        Some(coin) => {
                            QuerierResult::Ok(ContractResult::from(to_binary(&BalanceResponse {
                                amount: Coin {
                                    denom: coin.denom.clone(),
                                    amount: coin.amount,
                                },
                            })))
                        }
                        None => QuerierResult::Err(SystemError::InvalidRequest {
                            error: "balance not found".to_string(),
                            request: Default::default(),
                        }),
                    }
                } else if address == &String::from("reward") && denom == "uusd" {
                    let bank_res = BalanceResponse {
                        amount: Coin {
                            amount: Uint128::from(2000u128),
                            denom: denom.to_string(),
                        },
                    };
                    QuerierResult::Ok(ContractResult::from(to_binary(&bank_res)))
                } else {
                    self.base.handle_query(request)
                }
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

    pub fn query<T: DeserializeOwned>(&self, request: &QueryRequest<Empty>) -> StdResult<T> {
        self.custom_query(request)
    }

    /// Makes the query and parses the response. Also handles custom queries,
    /// so you need to specify the custom query type in the function parameters.
    /// If you are no using a custom query, just use `query` for easier interface.
    ///
    /// Any error (System Error, Error or called contract, or Parse Error) are flattened into
    /// one level. Only use this if you don't need to check the SystemError
    /// eg. If you don't differentiate between contract missing and contract returned error
    pub fn custom_query<C: CustomQuery, U: DeserializeOwned>(
        &self,
        request: &QueryRequest<C>,
    ) -> StdResult<U> {
        let raw = to_vec(request).map_err(|serialize_err| {
            StdError::generic_err(format!("Serializing QueryRequest: {}", serialize_err))
        })?;
        match self.raw_query(&raw) {
            SystemResult::Err(system_err) => Err(StdError::generic_err(format!(
                "Querier system error: {}",
                system_err
            ))),
            SystemResult::Ok(ContractResult::Err(contract_err)) => Err(StdError::generic_err(
                format!("Querier contract error: {}", contract_err),
            )),
            SystemResult::Ok(ContractResult::Ok(value)) => from_binary(&value),
        }
    }
}

#[derive(Clone, Default)]
pub struct BalanceQuerier {
    balances: HashMap<String, Coin>,
}

impl BalanceQuerier {
    pub fn new(balances: &[(String, Coin)]) -> Self {
        BalanceQuerier {
            balances: native_balances_to_map(balances),
        }
    }
}

#[derive(Clone, Default)]
pub struct TokenQuerier {
    balances: HashMap<String, HashMap<String, Uint128>>,
}

impl TokenQuerier {
    pub fn new(balances: &[(&String, &[(&String, &Uint128)])]) -> Self {
        TokenQuerier {
            balances: balances_to_map(balances),
        }
    }
}

pub(crate) fn native_balances_to_map(balances: &[(String, Coin)]) -> HashMap<String, Coin> {
    let mut balances_map: HashMap<String, Coin> = HashMap::new();
    for (contract_addr, balances) in balances.iter() {
        let coin = Coin {
            denom: balances.clone().denom,
            amount: balances.clone().amount,
        };
        balances_map.insert(String::from(contract_addr), coin);
    }
    balances_map
}

pub(crate) fn balances_to_map(
    balances: &[(&String, &[(&String, &Uint128)])],
) -> HashMap<String, HashMap<String, Uint128>> {
    let mut balances_map: HashMap<String, HashMap<String, Uint128>> = HashMap::new();
    for (contract_addr, balances) in balances.iter() {
        let mut contract_balances_map: HashMap<String, Uint128> = HashMap::new();
        for (addr, balance) in balances.iter() {
            contract_balances_map.insert(addr.to_string(), **balance);
        }

        balances_map.insert(contract_addr.to_string(), contract_balances_map);
    }
    balances_map
}

impl WasmMockQuerier {
    pub fn new(base: MockQuerier<CustomQueryWrapper>) -> Self {
        WasmMockQuerier {
            base,
            token_querier: TokenQuerier::default(),
            balance_querier: BalanceQuerier::default(),
            validators: vec![],
            tokenize_share_records: vec![],
        }
    }

    pub fn with_native_balances(&mut self, balances: &[(String, Coin)]) {
        self.balance_querier = BalanceQuerier::new(balances);
        for (addr, balance) in balances {
            self.base.update_balance(addr, vec![balance.clone()]);
        }
    }

    // configure the mint whitelist mock basset
    pub fn with_token_balances(&mut self, balances: &[(&String, &[(&String, &Uint128)])]) {
        self.token_querier = TokenQuerier::new(balances);
    }

    pub fn add_validator(&mut self, validator: RegistryValidator) {
        self.validators.push(validator);
    }

    pub fn add_tokenize_share_record(&mut self, record: TokenizeShareRecord) {
        self.tokenize_share_records.push(record);
    }
}
