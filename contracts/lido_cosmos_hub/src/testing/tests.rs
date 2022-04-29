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

//! This integration test tries to run and call the generated wasm.
//! It depends on a Wasm build being available, which you can create with `cargo wasm`.
//! Then running `cargo integration-test` will validate we can properly call into that generated Wasm.
//!
//! You can easily convert unit tests to integration tests as follows:
//! 1. Copy them over verbatim
//! 2. Then change
//!      let mut deps = mock_dependencies &[]);
//!    to
//!      let mut deps = mock_instance(WASM, &[]);
//! 3. If you access raw storage, where ever you see something like:
//!      deps.storage.get(CONFIG_KEY).expect("no data stored");
//!    replace it with:
//!      deps.with_storage(|store| {
//!          let data = store.get(CONFIG_KEY).expect("no data stored");
//!          //...
//!      });
//! 4. Anywhere you see query(deps.as_ref(), ...) you must replace it with query(deps.as_mut(), ...)
use cosmwasm_std::{
    coin, coins, from_binary, to_binary, Addr, Api, BankMsg, Binary, Coin, CosmosMsg, Decimal,
    DepsMut, DistributionMsg, Env, FullDelegation, MessageInfo, OwnedDeps, Querier, QueryRequest,
    Reply, Response, StakingMsg, StdError, Storage, SubMsgExecutionResponse, SubMsgResult, Uint128,
    Validator, WasmMsg, WasmQuery,
};
use lido_cosmos_validators_registry::msg::QueryMsg as QueryValidators;
use lido_cosmos_validators_registry::registry::ValidatorResponse as RegistryValidator;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contract::{execute, instantiate, query, reply, MAX_PAUSE_DURATION};
use cosmwasm_std::testing::{mock_env, mock_info};
use protobuf::Message;

use cw20::{Cw20ExecuteMsg, Cw20ReceiveMsg};
use cw20_base::msg::ExecuteMsg::Mint;

use crate::tokenized::{
    build_redeem_tokenize_share_msg, get_module_address, TOKENIZE_SHARES_PATH,
    TOKENIZE_SHARES_REPLY_ID,
};

use super::mock_querier::{mock_dependencies as dependencies, WasmMockQuerier};
use crate::state::{CONFIG, TOKENIZED_SHARE_RECIPIENT};
use lido_cosmos_rewards_dispatcher::msg::ExecuteMsg::DispatchRewards;

use super::mock_api::MockApi;
use crate::testing::mock_querier::{
    LARGEST_VALIDATOR, MAX_VALIDATOR_STAKED, TOKENIZED_SHARES_SUPPLY,
};
use crate::tokenize_share_record::{
    Coin as ProtoCoin, MsgTokenizeShares, MsgTokenizeSharesResponse, TokenizeShareRecord,
};
use crate::tokenized::execute_unbond_statom;
use basset::hub::Cw20HookMsg::Unbond;
use basset::hub::ExecuteMsg::{CheckSlashing, Receive, UpdateConfig, UpdateParams};
use basset::hub::QueryMsg::{Config, Parameters as Params, State};
use basset::hub::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, Parameters, QueryMsg, StateResponse,
};
use cosmwasm_std::testing::MockStorage;
use std::borrow::BorrowMut;
use std::ops::Mul;

const DEFAULT_VALIDATOR: &str = "default-validator";
const DEFAULT_VALIDATOR2: &str = "default-validator2000";
const DEFAULT_VALIDATOR3: &str = "default-validator3000";

pub const MOCK_CONTRACT_ADDR: &str = "cosmos2contract";

//pub const _INITIAL_DEPOSIT_AMOUNT: Uint128 = Uint128::from(1000000u128);

fn sample_validator<U: Into<String>>(addr: U) -> Validator {
    Validator {
        address: addr.into(),
        commission: Decimal::percent(3),
        max_commission: Decimal::percent(10),
        max_change_rate: Decimal::percent(1),
    }
}

fn set_validator_mock(querier: &mut WasmMockQuerier) {
    querier.update_staking(
        "uatom",
        &[
            sample_validator(DEFAULT_VALIDATOR),
            sample_validator(DEFAULT_VALIDATOR2),
            sample_validator(DEFAULT_VALIDATOR3),
        ],
        &[],
    );
}

pub fn initialize<S: Storage, A: Api, Q: Querier>(
    deps: &mut OwnedDeps<S, A, Q>,
    owner: String,
    reward_contract: String,
    statom_token_contract: String,
) {
    let msg = InstantiateMsg {
        underlying_coin_denom: "uatom".to_string(),
        max_burn_ratio: Decimal::from_ratio(Uint128::new(10), Uint128::new(100)),
    };

    let owner_info = mock_info(owner.as_str(), &[]);
    instantiate(deps.as_mut(), mock_env(), owner_info.clone(), msg).unwrap();

    let register_msg = ExecuteMsg::UpdateConfig {
        owner: None,
        rewards_dispatcher_contract: Some(reward_contract),
        statom_token_contract: Some(statom_token_contract),
        validators_registry_contract: Some(String::from("validators_registry")),
    };
    let res = execute(deps.as_mut(), mock_env(), owner_info, register_msg).unwrap();
    assert_eq!(1, res.messages.len());
}

pub fn do_register_validator(
    deps: &mut OwnedDeps<MockStorage, MockApi, WasmMockQuerier>,
    validator: Validator,
) {
    deps.querier.add_validator(RegistryValidator {
        total_delegated: Default::default(),
        address: validator.address,
    });
}

pub fn do_register_tokenize_share_record(
    deps: &mut OwnedDeps<MockStorage, MockApi, WasmMockQuerier>,
    record: TokenizeShareRecord,
) {
    deps.querier.add_tokenize_share_record(record);
}

impl TokenizeShareRecord {
    pub fn new_tokenize_share(
        id: u64,
        owner: String,
        module_account: String,
        denom: String,
        validator: String,
    ) -> TokenizeShareRecord {
        let mut record = TokenizeShareRecord::new();

        record.set_id(id);
        record.set_owner(owner);
        record.set_module_account(module_account);
        record.set_share_token_denom(denom);
        record.set_validator(validator);

        record
    }
}
pub fn do_bond_statom(
    deps: &mut OwnedDeps<MockStorage, MockApi, WasmMockQuerier>,
    addr: String,
    amount: Uint128,
) {
    let validators: Vec<RegistryValidator> = deps
        .querier
        .query(&QueryRequest::Wasm(WasmQuery::Smart {
            contract_addr: String::from("validators_registry"),
            msg: to_binary(&QueryValidators::GetValidatorsForDelegation {}).unwrap(),
        }))
        .unwrap();

    let bond = ExecuteMsg::BondForStAtom {};

    let info = mock_info(&addr, &[coin(amount.u128(), "uatom")]);
    let res = execute(deps.as_mut(), mock_env(), info, bond).unwrap();
    assert_eq!(validators.len() + 1, res.messages.len());
}

pub fn do_unbond(
    deps: DepsMut,
    addr: String,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Response {
    let successful_bond = Unbond {};
    let receive = Receive(Cw20ReceiveMsg {
        sender: addr,
        amount,
        msg: to_binary(&successful_bond).unwrap(),
    });

    execute(deps, env, info, receive).unwrap()
}

/// Covers if all the fields of InstantiateMsg are stored in
/// parameters' storage, the config storage stores the creator,
/// the current batch storage and state are initialized.
#[test]
fn proper_initialization() {
    let mut deps = dependencies(&[]);

    let _validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    // successful call
    let msg = InstantiateMsg {
        underlying_coin_denom: "uatom".to_string(),
        max_burn_ratio: Decimal::from_ratio(Uint128::new(10), Uint128::new(100)),
    };

    let owner = String::from("owner1");
    let owner_info = mock_info(owner.as_str(), &[]);

    // we can just call .unwrap() to assert this was a success
    let res: Response = instantiate(deps.as_mut(), mock_env(), owner_info, msg).unwrap();
    assert_eq!(0, res.messages.len());

    // check parameters storage
    let params = Params {};
    let query_params: Parameters =
        from_binary(&query(deps.as_ref(), mock_env(), params).unwrap()).unwrap();
    assert_eq!(query_params.underlying_coin_denom, "uatom");

    // state storage must be initialized
    let state = State {};
    let query_state: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), state).unwrap()).unwrap();
    let expected_result = StateResponse {
        statom_exchange_rate: Decimal::one(),
        total_bond_statom_amount: Uint128::zero(),
        prev_hub_balance: Default::default(),
        last_processed_batch: 0u64,
    };
    assert_eq!(query_state, expected_result);

    // config storage must be initialized
    let conf = Config {};
    let query_conf: ConfigResponse =
        from_binary(&query(deps.as_ref(), mock_env(), conf).unwrap()).unwrap();
    let expected_conf = ConfigResponse {
        owner: String::from("owner1"),
        reward_dispatcher_contract: None,
        validators_registry_contract: None,
        statom_token_contract: None,
    };

    assert_eq!(expected_conf, query_conf);
}

#[test]
fn proper_bond_for_st_atom() {
    let mut deps = dependencies(&[]);

    let validator = sample_validator(DEFAULT_VALIDATOR);
    let validator2 = sample_validator(DEFAULT_VALIDATOR2);
    let validator3 = sample_validator(DEFAULT_VALIDATOR3);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");
    let bond_amount = Uint128::from(10000u64);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator);
    do_register_validator(&mut deps, validator2);
    do_register_validator(&mut deps, validator3);

    let bond_msg = ExecuteMsg::BondForStAtom {};

    let info = mock_info(&addr1, &[coin(bond_amount.u128(), "uatom")]);

    let res = execute(deps.as_mut(), mock_env(), info, bond_msg).unwrap();
    assert_eq!(4, res.messages.len());

    // set bob's balance in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &bond_amount)])]);

    let delegate = &res.messages[0];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR);
            assert_eq!(amount, coin(3334, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    let delegate = &res.messages[1];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR2);
            assert_eq!(amount, coin(3333, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    let delegate = &res.messages[2];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR3);
            assert_eq!(amount, coin(3333, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    let mint = &res.messages[3];
    match mint.msg.clone() {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds: _,
        }) => {
            assert_eq!(contract_addr, statom_token_contract);
            assert_eq!(
                msg,
                to_binary(&Cw20ExecuteMsg::Mint {
                    recipient: addr1.clone(),
                    amount: bond_amount,
                })
                .unwrap()
            )
        }
        _ => panic!("Unexpected message: {:?}", mint),
    }

    // get total bonded
    let state = State {};
    let query_state: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), state).unwrap()).unwrap();
    assert_eq!(query_state.total_bond_statom_amount, bond_amount);
    assert_eq!(query_state.statom_exchange_rate, Decimal::one());

    // no-send funds
    let bob = String::from("bob");
    let failed_bond = ExecuteMsg::BondForStAtom {};

    let info = mock_info(&bob, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, failed_bond);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("No uatom assets are provided to bond")
    );

    // send other tokens than atom funds
    let bob = String::from("bob");
    let failed_bond = ExecuteMsg::BondForStAtom {};

    let info = mock_info(&bob, &[coin(10, "ukrt")]);
    let res = execute(deps.as_mut(), mock_env(), info, failed_bond.clone());
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("No uatom assets are provided to bond")
    );

    // bond with more than one coin is not possible
    let info = mock_info(
        &addr1,
        &[
            coin(bond_amount.u128(), "uatom"),
            coin(bond_amount.u128(), "uusd"),
        ],
    );

    let res = execute(deps.as_mut(), mock_env(), info, failed_bond).unwrap_err();
    assert_eq!(
        res,
        StdError::generic_err("More than one coin is sent; only one asset is supported")
    );
}

#[test]
fn proper_bond_rewards() {
    let mut deps = dependencies(&[]);

    let validator = sample_validator(DEFAULT_VALIDATOR);
    let validator2 = sample_validator(DEFAULT_VALIDATOR2);
    let validator3 = sample_validator(DEFAULT_VALIDATOR3);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");
    let bond_amount = Uint128::from(10000u64);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_dispatcher_contract = String::from("reward_dispatcher");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_dispatcher_contract.clone(),
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());
    do_register_validator(&mut deps, validator2.clone());
    do_register_validator(&mut deps, validator3.clone());

    let bond_msg = ExecuteMsg::BondForStAtom {};

    let info = mock_info(&addr1, &[coin(bond_amount.u128(), "uatom")]);

    let res = execute(deps.as_mut(), mock_env(), info, bond_msg).unwrap();
    assert_eq!(4, res.messages.len());

    // set bob's balance in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &bond_amount)])]);

    let bond_msg = ExecuteMsg::BondRewards {};

    let info = mock_info(
        &reward_dispatcher_contract,
        &[coin(bond_amount.u128(), "uatom")],
    );

    let res = execute(deps.as_mut(), mock_env(), info, bond_msg).unwrap();
    assert_eq!(3, res.messages.len());

    let delegate = &res.messages[0];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR);
            assert_eq!(amount, coin(3334, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    let delegate = &res.messages[1];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR2);
            assert_eq!(amount, coin(3333, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    let delegate = &res.messages[2];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR3);
            assert_eq!(amount, coin(3333, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    let delegations: [FullDelegation; 3] = [
        (sample_delegation(DEFAULT_VALIDATOR.to_string(), coin(6666, "uatom"))),
        (sample_delegation(DEFAULT_VALIDATOR2.to_string(), coin(6666, "uatom"))),
        (sample_delegation(DEFAULT_VALIDATOR3.to_string(), coin(6668, "uatom"))),
    ];

    let validators: [Validator; 3] = [validator, validator2, validator3];

    set_delegation_query(&mut deps.querier, &delegations, &validators);

    // set bob's balance to 10 in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &bond_amount)])]);

    // get total bonded
    let state = State {};
    let query_state: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), state).unwrap()).unwrap();
    assert_eq!(
        query_state.total_bond_statom_amount,
        bond_amount + bond_amount // BondForStAtom + BondRewards
    );
    assert_eq!(
        query_state.statom_exchange_rate,
        Decimal::from_ratio(2u128, 1u128)
    );

    // no-send funds
    let failed_bond = ExecuteMsg::BondRewards {};

    let info = mock_info(&reward_dispatcher_contract, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, failed_bond);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("No uatom assets are provided to bond")
    );

    // send other tokens than atom funds
    let failed_bond = ExecuteMsg::BondRewards {};

    let info = mock_info(&reward_dispatcher_contract, &[coin(10, "ukrt")]);
    let res = execute(deps.as_mut(), mock_env(), info, failed_bond.clone());
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("No uatom assets are provided to bond")
    );

    // bond with more than one coin is not possible
    let info = mock_info(
        &reward_dispatcher_contract,
        &[
            coin(bond_amount.u128(), "uatom"),
            coin(bond_amount.u128(), "uusd"),
        ],
    );

    let res = execute(deps.as_mut(), mock_env(), info, failed_bond).unwrap_err();
    assert_eq!(
        res,
        StdError::generic_err("More than one coin is sent; only one asset is supported")
    );

    // bond from non-dispatcher address
    let info = mock_info(
        &String::from("random_address"),
        &[coin(bond_amount.u128(), "uatom")],
    );
    let failed_bond = ExecuteMsg::BondRewards {};

    let res = execute(deps.as_mut(), mock_env(), info, failed_bond).unwrap_err();
    assert_eq!(res, StdError::generic_err("unauthorized"));
}

/// Covers if Withdraw message, swap message, and dispatch rewards are sent.
#[test]
pub fn proper_update_global_index() {
    let mut deps = dependencies(&[]);
    let validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");
    let bond_amount = Uint128::from(10u64);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract.clone(),
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());

    deps.querier
        .with_token_balances(&[(&String::from("token"), &[]), (&statom_token_contract, &[])]);

    // fails if there is no delegation
    let reward_msg = ExecuteMsg::DispatchRewards {};

    let info = mock_info(&addr1, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, reward_msg).unwrap();
    assert_eq!(res.messages.len(), 1);

    // bond
    do_bond_statom(&mut deps, addr1.clone(), bond_amount);

    // set bob's balance to 10 in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &bond_amount)])]);

    // set delegation for query-all-delegation
    let delegations: [FullDelegation; 1] = [(sample_delegation(
        validator.address.clone(),
        coin(bond_amount.u128() * 2, "uatom"),
    ))];

    let validators: [Validator; 1] = [(validator.clone())];

    set_delegation_query(&mut deps.querier, &delegations, &validators);

    // set bob's balance to 10 in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &bond_amount)])]);

    let reward_msg = ExecuteMsg::DispatchRewards {};

    let info = mock_info(&addr1, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, reward_msg).unwrap();
    assert_eq!(2, res.messages.len());

    let withdraw = &res.messages[0];
    match withdraw.msg.clone() {
        CosmosMsg::Distribution(DistributionMsg::WithdrawDelegatorReward { validator: val }) => {
            assert_eq!(val, validator.address);
        }
        _ => panic!("Unexpected message: {:?}", withdraw),
    }

    let update_g_index = &res.messages[1];
    match update_g_index.msg.clone() {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds: _,
        }) => {
            assert_eq!(contract_addr, reward_contract);
            assert_eq!(msg, to_binary(&DispatchRewards {}).unwrap())
        }
        _ => panic!("Unexpected message: {:?}", update_g_index),
    }
}

/// Covers update_global_index when there is more than one validator.
/// Checks if more than one Withdraw message is sent.
#[test]
pub fn proper_update_global_index_two_validators() {
    let mut deps = dependencies(&[]);
    let validator = sample_validator(DEFAULT_VALIDATOR);
    let validator2 = sample_validator(DEFAULT_VALIDATOR2);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());

    // bond
    do_bond_statom(&mut deps, addr1.clone(), Uint128::from(10u64));

    // set bob's balance to 10 in token contract
    deps.querier.with_token_balances(&[
        (&String::from("token"), &[(&addr1, &Uint128::from(10u128))]),
        (&statom_token_contract, &[(&addr1, &Uint128::from(10u64))]),
    ]);

    // register_validator
    do_register_validator(&mut deps, validator2.clone());

    // bond to the second validator
    do_bond_statom(&mut deps, addr1.clone(), Uint128::from(10u64));

    // set delegation for query-all-delegation
    let delegations: [FullDelegation; 2] = [
        (sample_delegation(validator.address.clone(), coin(10, "uatom"))),
        (sample_delegation(validator2.address.clone(), coin(10, "uatom"))),
    ];

    let validators: [Validator; 2] = [(validator.clone()), (validator2.clone())];
    set_delegation_query(&mut deps.querier, &delegations, &validators);

    // set bob's balance to 10 in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &Uint128::from(10u64))])]);

    let reward_msg = ExecuteMsg::DispatchRewards {};

    let info = mock_info(&addr1, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, reward_msg).unwrap();
    assert_eq!(3, res.messages.len());

    let withdraw = &res.messages[0];
    match withdraw.msg.clone() {
        CosmosMsg::Distribution(DistributionMsg::WithdrawDelegatorReward { validator: val }) => {
            assert_eq!(val, validator.address);
        }
        _ => panic!("Unexpected message: {:?}", withdraw),
    }

    let withdraw = &res.messages[1];
    match withdraw.msg.clone() {
        CosmosMsg::Distribution(DistributionMsg::WithdrawDelegatorReward { validator: val }) => {
            assert_eq!(val, validator2.address);
        }
        _ => panic!("Unexpected message: {:?}", withdraw),
    }
}

/// Covers update_global_index when more than on validator is registered, but
/// there is only a delegation to only one of them.
/// Checks if one Withdraw message is sent.
#[test]
pub fn proper_update_global_index_respect_one_registered_validator() {
    let mut deps = dependencies(&[]);
    let validator = sample_validator(DEFAULT_VALIDATOR);
    let validator2 = sample_validator(DEFAULT_VALIDATOR2);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());

    // bond
    do_bond_statom(&mut deps, addr1.clone(), Uint128::from(10u64));

    // set bob's balance to 10 in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &Uint128::from(10u64))])]);

    // register_validator 2 but will not bond anything to it
    do_register_validator(&mut deps, validator2);

    // set delegation for query-all-delegation
    let delegations: [FullDelegation; 1] =
        [(sample_delegation(validator.address.clone(), coin(10, "uatom")))];

    let validators: [Validator; 1] = [(validator.clone())];
    set_delegation_query(&mut deps.querier, &delegations, &validators);

    // set bob's balance to 10 in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&addr1, &Uint128::from(10u64))])]);

    let reward_msg = ExecuteMsg::DispatchRewards {};

    let info = mock_info(&addr1, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, reward_msg).unwrap();
    assert_eq!(2, res.messages.len());

    let withdraw = &res.messages[0];
    match withdraw.msg.clone() {
        CosmosMsg::Distribution(DistributionMsg::WithdrawDelegatorReward { validator: val }) => {
            assert_eq!(val, validator.address);
        }
        _ => panic!("Unexpected message: {:?}", withdraw),
    }
}

/// Covers if the receive message is sent by token contract,
/// if handle_unbond is executed.
/*
    A comprehensive test for unbond is prepared in proper_unbond tests
*/
#[test]
pub fn proper_receive_statom() {
    let mut deps = dependencies(&[]);
    let validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr0001");
    let invalid = String::from("invalid");

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());

    // bond to the second validator
    do_bond_statom(&mut deps, addr1.clone(), MAX_VALIDATOR_STAKED);
    set_delegation(
        &mut deps.querier,
        validator,
        MAX_VALIDATOR_STAKED.u128(),
        "uatom",
    );

    // set bob's balance to 10 in token contract
    deps.querier.with_token_balances(&[
        (&statom_token_contract, &[(&addr1, &MAX_VALIDATOR_STAKED)]),
        (&String::from("token"), &[]),
    ]);

    // Null message
    let receive = Receive(Cw20ReceiveMsg {
        sender: addr1.clone(),
        amount: MAX_VALIDATOR_STAKED,
        msg: to_binary(&{}).unwrap(),
    });

    let token_info = mock_info(&statom_token_contract, &[]);
    let res = execute(deps.as_mut(), mock_env(), token_info, receive);
    assert!(res.is_err());

    // unauthorized
    let failed_unbond = Unbond {};
    let receive = Receive(Cw20ReceiveMsg {
        sender: addr1.clone(),
        amount: MAX_VALIDATOR_STAKED,
        msg: to_binary(&failed_unbond).unwrap(),
    });

    let invalid_info = mock_info(&invalid, &[]);
    let res = execute(deps.as_mut(), mock_env(), invalid_info, receive);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    // try to burn more than max_burn_ratio
    let params: Parameters =
        from_binary(&query(deps.as_ref(), mock_env(), Params {}).unwrap()).unwrap();
    let failed_unbond = Unbond {};
    let receive = Receive(Cw20ReceiveMsg {
        sender: addr1.clone(),
        amount: MAX_VALIDATOR_STAKED.mul(params.max_burn_ratio) + Uint128::new(1),
        msg: to_binary(&failed_unbond).unwrap(),
    });

    let invalid_info = mock_info(&statom_token_contract, &[]);
    let res = execute(deps.as_mut(), mock_env(), invalid_info, receive);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("Can not burn more than 0.1 of the top validator's stake, which is currently 2000 uatom")
    );

    // successful call
    let successful_unbond = Unbond {};
    let receive = Receive(Cw20ReceiveMsg {
        sender: addr1.clone(),
        amount: Uint128::from(10u64),
        msg: to_binary(&successful_unbond).unwrap(),
    });

    let valid_info = mock_info(&statom_token_contract, &[]);
    let res = execute(deps.as_mut(), mock_env(), valid_info, receive).unwrap();
    assert_eq!(res.messages.len(), 2);

    let msg = &res.messages[0];
    match msg.msg.clone() {
        CosmosMsg::Stargate { type_url, value } => {
            assert_eq!(TOKENIZE_SHARES_PATH, type_url);

            let encoded_tokenize_msg = build_binary_tokenize_shares_message(
                MOCK_CONTRACT_ADDR,
                LARGEST_VALIDATOR,
                addr1.as_str(),
                "10",
                "uatom",
            );

            assert_eq!(encoded_tokenize_msg, value);
        }
        _ => panic!("Unexpected message: {:?}", msg),
    }
}

#[test]
pub fn proper_reply() {
    let bob = "bob";
    let expected_denom = "valoperxXx12345";
    let expected_amount = Uint128::new(10);

    let mut deps = dependencies(&[]);
    set_validator_mock(&mut deps.querier);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract,
    );

    TOKENIZED_SHARE_RECIPIENT
        .save(deps.storage.borrow_mut(), &"bob".to_string())
        .unwrap();

    let mut response_msg = MsgTokenizeSharesResponse::new();

    let mut proto_coin = ProtoCoin::new();
    proto_coin.set_amount(expected_amount.to_string());
    proto_coin.set_denom(expected_denom.to_string());
    response_msg.set_amount(proto_coin);

    let encoded_response_msg = Binary::from(response_msg.write_to_bytes().unwrap());

    let res = reply(
        deps.as_mut(),
        mock_env(),
        Reply {
            id: TOKENIZE_SHARES_REPLY_ID,
            result: SubMsgResult::Ok(SubMsgExecutionResponse {
                events: vec![],
                data: Some(encoded_response_msg),
            }),
        },
    )
    .unwrap();
    assert_eq!(1, res.messages.len());
    let msg = &res.messages[0];
    match msg.msg.clone() {
        CosmosMsg::Bank(BankMsg::Send { to_address, amount }) => {
            assert_eq!(bob, to_address);
            assert_eq!(expected_amount, amount[0].amount);
            assert_eq!(expected_denom, amount[0].denom);
        }
        _ => panic!("Unexpected message: {:?}", msg),
    }
}

/// Covers if the epoch period is passed, Tokenize/burn messages are sent,
/// the state storage is updated to the new changed value,
/// the current epoch is updated to the new values,
/// the request is stored in unbond wait list, and unbond history map is updated
#[test]
pub fn proper_unbond_statom() {
    let mut deps = dependencies(&[]);
    let validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());

    let bob = String::from("bob");
    let bond = ExecuteMsg::BondForStAtom {};

    let info = mock_info(&bob, &[coin(10, "uatom")]);

    let res = execute(deps.as_mut(), mock_env(), info, bond).unwrap();
    assert_eq!(2, res.messages.len());

    let delegate = &res.messages[0];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR);
            assert_eq!(amount, coin(10, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    // set bob's balance to 10 in token contract
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&bob, &Uint128::from(10u128))])]);

    set_delegation(&mut deps.querier, validator, 10, "uatom");

    let token_info = mock_info(&statom_token_contract, &[]);

    // check the state before unbond
    let state = State {};
    let query_state: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), state).unwrap()).unwrap();
    assert_eq!(query_state.total_bond_statom_amount, Uint128::from(10u64));

    // successful call
    let successful_unbond = Unbond {};
    let receive = Receive(Cw20ReceiveMsg {
        sender: bob.clone(),
        amount: Uint128::from(1u64),
        msg: to_binary(&successful_unbond).unwrap(),
    });
    let res = execute(deps.as_mut(), mock_env(), token_info, receive).unwrap();
    assert_eq!(2, res.messages.len());
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&bob, &Uint128::from(9u128))])]);

    let recipient = TOKENIZED_SHARE_RECIPIENT.load(&deps.storage).unwrap();
    assert_eq!(recipient, bob);

    // successful call
    let successful_unbond = Unbond {};
    let receive = Receive(Cw20ReceiveMsg {
        sender: bob.clone(),
        amount: Uint128::from(5u64),
        msg: to_binary(&successful_unbond).unwrap(),
    });
    let token_info = mock_info(&statom_token_contract, &[]);
    let res = execute(deps.as_mut(), mock_env(), token_info, receive).unwrap();
    assert_eq!(2, res.messages.len());
    deps.querier
        .with_token_balances(&[(&statom_token_contract, &[(&bob, &Uint128::from(4u128))])]);

    let msg = &res.messages[0];
    match msg.msg.clone() {
        CosmosMsg::Stargate { type_url, value } => {
            assert_eq!(TOKENIZE_SHARES_PATH, type_url);

            let encoded_tokenize_msg = build_binary_tokenize_shares_message(
                MOCK_CONTRACT_ADDR,
                LARGEST_VALIDATOR,
                bob.as_str(),
                "5",
                "uatom",
            );

            assert_eq!(encoded_tokenize_msg, value);
        }
        _ => panic!("Unexpected message: {:?}", msg),
    }

    // check the state
    let state = State {};
    let query_state: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), state).unwrap()).unwrap();
    assert_eq!(query_state.total_bond_statom_amount, Uint128::from(4u64));
}

/// Covers if the undelegate function sends different Undelegate messages
/// to different validators, when a validator does not have enough delegation.
#[test]
pub fn proper_undelegate() {
    let mut deps = dependencies(&[]);

    let addr1 = String::from("addr1000");
    let addr2 = String::from("addr2000");
    let addr3 = String::from("addr3000");

    // create 3 validators
    let validator = sample_validator(DEFAULT_VALIDATOR);
    let validator2 = sample_validator(DEFAULT_VALIDATOR2);
    let validator3 = sample_validator(DEFAULT_VALIDATOR3);

    set_validator_mock(&mut deps.querier);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    do_register_validator(&mut deps, validator.clone());
    do_register_validator(&mut deps, validator2.clone());
    do_register_validator(&mut deps, validator3.clone());

    // bond to a validator
    do_bond_statom(&mut deps, addr1.clone(), Uint128::from(10u64));
    do_bond_statom(&mut deps, addr2.clone(), Uint128::from(150u64));
    do_bond_statom(&mut deps, addr3.clone(), Uint128::from(200u64));

    // give validators different delegation amount
    let delegations: [FullDelegation; 3] = [
        (sample_delegation(validator.address.clone(), coin(10, "uatom"))),
        (sample_delegation(validator2.address.clone(), coin(150, "uatom"))),
        (sample_delegation(validator3.address.clone(), coin(200, "uatom"))),
    ];

    let validators: [Validator; 3] = [(validator), (validator2), (validator3)];
    set_delegation_query(&mut deps.querier, &delegations, &validators);
    deps.querier.with_token_balances(&[(
        &statom_token_contract,
        &[
            (&addr3, &Uint128::from(200u64)),
            (&addr2, &Uint128::from(150u64)),
            (&addr1, &Uint128::from(10u64)),
        ],
    )]);

    // send the first burn
    let token_info = mock_info(&statom_token_contract, &[]);
    let mut env = mock_env();
    let res = do_unbond(
        deps.as_mut(),
        addr2.clone(),
        env.clone(),
        token_info.clone(),
        Uint128::from(50u64),
    );
    assert_eq!(res.messages.len(), 2);

    deps.querier.with_token_balances(&[(
        &statom_token_contract,
        &[
            (&addr3, &Uint128::from(200u64)),
            (&addr2, &Uint128::from(100u64)),
            (&addr1, &Uint128::from(10u64)),
        ],
    )]);

    env.block.time = env.block.time.plus_seconds(40);

    // send the second burn
    let res = do_unbond(
        deps.as_mut(),
        addr2.clone(),
        env,
        token_info,
        Uint128::from(100u64),
    );

    assert_eq!(res.messages.len(), 2);

    deps.querier.with_token_balances(&[(
        &statom_token_contract,
        &[
            (&addr3, &Uint128::from(200u64)),
            (&addr2, &Uint128::from(0u64)),
            (&addr1, &Uint128::from(10u64)),
        ],
    )]);

    match res.messages[0].msg.clone() {
        CosmosMsg::Stargate { type_url, value } => {
            assert_eq!(TOKENIZE_SHARES_PATH, type_url);

            let encoded_tokenize_msg = build_binary_tokenize_shares_message(
                MOCK_CONTRACT_ADDR,
                LARGEST_VALIDATOR,
                addr2.as_str(),
                "100",
                "uatom",
            );

            assert_eq!(encoded_tokenize_msg, value);
        }
        _ => panic!("Unexpected message: {:?}", res.messages[0].msg),
    }
}

/// Covers if the undelegate function sends different Undelegate messages
/// if the delegations of the user are distributed to several validators
/// and if the user wants to unbond amount that none of validators has.
#[test]
pub fn proper_undelegate_respect_distributed_delegation() {
    let mut deps = dependencies(&[]);

    let addr1 = String::from("addr1000");
    let addr2 = String::from("addr2000");

    // create 3 validators
    let validator = sample_validator(DEFAULT_VALIDATOR);
    let validator2 = sample_validator(DEFAULT_VALIDATOR2);
    let validator3 = sample_validator(DEFAULT_VALIDATOR3);

    set_validator_mock(&mut deps.querier);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    do_register_validator(&mut deps, validator.clone());
    do_register_validator(&mut deps, validator2.clone());
    do_register_validator(&mut deps, validator3);

    // bond to a validator
    do_bond_statom(&mut deps, addr1.clone(), Uint128::from(1000u64));
    do_bond_statom(&mut deps, addr1.clone(), Uint128::from(1500u64));

    // give validators different delegation amount
    let delegations: [FullDelegation; 2] = [
        (sample_delegation(validator.address.clone(), coin(1000, "uatom"))),
        (sample_delegation(validator2.address.clone(), coin(1500, "uatom"))),
    ];

    let validators: [Validator; 2] = [(validator), (validator2)];
    set_delegation_query(&mut deps.querier, &delegations, &validators);

    deps.querier.with_token_balances(&[
        (&String::from("token"), &[(&addr1, &Uint128::from(2500u64))]),
        (&statom_token_contract, &[]),
    ]);

    // send the first burn
    let token_info = mock_info(&statom_token_contract, &[]);
    let mut env = mock_env();

    env.block.time = env.block.time.plus_seconds(40);

    let res = do_unbond(
        deps.as_mut(),
        addr2.clone(),
        env,
        token_info,
        Uint128::from(2000u64),
    );
    assert_eq!(res.messages.len(), 2);

    match res.messages[0].msg.clone() {
        CosmosMsg::Stargate { type_url, value } => {
            assert_eq!(TOKENIZE_SHARES_PATH, type_url);

            let encoded_tokenize_msg = build_binary_tokenize_shares_message(
                MOCK_CONTRACT_ADDR,
                LARGEST_VALIDATOR,
                addr2.as_str(),
                "2000",
                "uatom",
            );

            assert_eq!(encoded_tokenize_msg, value);
        }
        _ => panic!("Unexpected message: {:?}", res.messages[0].msg),
    }
}

/// Covers the effect of slashing of bond, unbond, and withdraw_unbonded
/// update the exchange rate after and before slashing.
#[test]
pub fn proper_slashing_statom() {
    let mut deps = dependencies(&[]);
    let validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");
    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());

    // bond
    do_bond_statom(&mut deps, addr1.clone(), Uint128::from(1000u64));

    // this will set the balance of the user in token contract
    deps.querier.with_token_balances(&[
        (
            &statom_token_contract,
            &[(&addr1, &Uint128::from(1000u128))],
        ),
        (&String::from("token"), &[]),
    ]);

    // slashing
    set_delegation(&mut deps.querier, validator.clone(), 900, "uatom");

    let info = mock_info(&addr1, &[]);
    let report_slashing = CheckSlashing {};
    let res = execute(deps.as_mut(), mock_env(), info, report_slashing).unwrap();
    assert_eq!(0, res.messages.len());

    let ex_rate = State {};
    let query_exchange_rate: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), ex_rate).unwrap()).unwrap();
    assert_eq!(query_exchange_rate.statom_exchange_rate.to_string(), "0.9");

    // bond again to see the update exchange rate
    let second_bond = ExecuteMsg::BondForStAtom {};

    let info = mock_info(&addr1, &[coin(900, "uatom")]);

    let res = execute(deps.as_mut(), mock_env(), info.clone(), second_bond).unwrap();
    assert_eq!(2, res.messages.len());

    let expected_er = "0.9";
    let ex_rate = State {};
    let query_exchange_rate: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), ex_rate).unwrap()).unwrap();
    assert_eq!(
        query_exchange_rate.statom_exchange_rate.to_string(),
        expected_er
    );

    let delegate = &res.messages[0];
    match delegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Delegate { validator, amount }) => {
            assert_eq!(validator.as_str(), DEFAULT_VALIDATOR);
            assert_eq!(amount, coin(900, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", delegate),
    }

    let message = &res.messages[1];
    match message.msg.clone() {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds: _,
        }) => {
            assert_eq!(contract_addr, statom_token_contract);
            assert_eq!(
                msg,
                to_binary(&Mint {
                    recipient: info.sender.to_string(),
                    amount: Uint128::from(1000u64)
                })
                .unwrap()
            );
        }
        _ => panic!("Unexpected message: {:?}", message),
    }

    set_delegation(&mut deps.querier, validator, 1800, "uatom");

    // update user balance
    deps.querier.with_token_balances(&[
        (
            &statom_token_contract,
            &[(&addr1, &Uint128::from(2000u128))],
        ),
        (&String::from("token"), &[]),
    ]);

    let mut env = mock_env();
    let _res = execute_unbond_statom(
        deps.as_mut(),
        env.clone(),
        Uint128::from(500u64),
        addr1.clone(),
    )
    .unwrap();

    deps.querier.with_token_balances(&[
        (
            &statom_token_contract,
            &[(&addr1, &Uint128::from(1500u128))],
        ),
        (&String::from("token"), &[]),
    ]);

    env.block.time = env.block.time.plus_seconds(31);
    execute_unbond_statom(
        deps.as_mut(),
        env.clone(),
        Uint128::from(500u64),
        addr1.clone(),
    )
    .unwrap();

    deps.querier.with_token_balances(&[(
        &statom_token_contract,
        &[(&addr1, &Uint128::from(1000u128))],
    )]);

    deps.querier.with_native_balances(&[(
        String::from(MOCK_CONTRACT_ADDR),
        Coin {
            denom: "uatom".to_string(),
            amount: Uint128::from(900u64),
        },
    )]);

    let ex_rate = State {};
    let query_exchange_rate: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), ex_rate).unwrap()).unwrap();
    assert_eq!(
        query_exchange_rate.statom_exchange_rate.to_string(),
        expected_er
    );

    env.block.time = env.block.time.plus_seconds(90);

    let ex_rate = State {};
    let query_exchange_rate: StateResponse =
        from_binary(&query(deps.as_ref(), mock_env(), ex_rate).unwrap()).unwrap();
    assert_eq!(
        query_exchange_rate.statom_exchange_rate.to_string(),
        expected_er
    );
}

/// Covers if the state/parameters storage is updated to the given value,
/// who sends the message, and if
/// RewardUpdateDenom message is sent to the reward contract
#[test]
pub fn test_update_params() {
    let mut deps = dependencies(&[]);

    let _validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    // test with no swap denom.
    let update_prams = UpdateParams {
        max_burn_ratio: Decimal::from_ratio(Uint128::new(10), Uint128::new(100)),
    };
    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract,
    );

    let invalid_info = mock_info(String::from("invalid").as_str(), &[]);
    let res = execute(
        deps.as_mut(),
        mock_env(),
        invalid_info,
        update_prams.clone(),
    );
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), mock_env(), creator_info, update_prams).unwrap();
    assert_eq!(res.messages.len(), 0);

    let params: Parameters =
        from_binary(&query(deps.as_ref(), mock_env(), Params {}).unwrap()).unwrap();
    assert_eq!(params.underlying_coin_denom, "uatom");

    let update_prams = UpdateParams {
        max_burn_ratio: Decimal::from_ratio(Uint128::new(20), Uint128::new(100)),
    };

    // the result must be 1
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), mock_env(), creator_info, update_prams).unwrap();
    assert_eq!(res.messages.len(), 0);

    let params: Parameters =
        from_binary(&query(deps.as_ref(), mock_env(), Params {}).unwrap()).unwrap();
    assert_eq!(
        params.max_burn_ratio,
        Decimal::from_ratio(Uint128::new(20), Uint128::new(100))
    );
}

/// Covers if the storage affected by update_config are updated properly
#[test]
pub fn proper_update_config() {
    let mut deps = dependencies(&[]);

    let _validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    let owner = String::from("owner1");
    let new_owner = String::from("new_owner");
    let invalid_owner = String::from("invalid_owner");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner.clone(),
        reward_contract.clone(),
        statom_token_contract.clone(),
    );

    let config = Config {};
    let config_query: ConfigResponse =
        from_binary(&query(deps.as_ref(), mock_env(), config).unwrap()).unwrap();

    // make sure the other configs are still the same.
    assert_eq!(
        &config_query.reward_dispatcher_contract.unwrap(),
        &reward_contract
    );
    assert_eq!(&config_query.owner, &owner);

    // only the owner can call this message
    let update_config = UpdateConfig {
        owner: Some(new_owner.clone()),
        rewards_dispatcher_contract: None,
        validators_registry_contract: None,
        statom_token_contract: None,
    };
    let info = mock_info(&invalid_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    // change the owner
    let update_config = UpdateConfig {
        owner: Some(new_owner.clone()),
        rewards_dispatcher_contract: None,
        validators_registry_contract: None,
        statom_token_contract: None,
    };
    let info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config).unwrap();
    assert_eq!(res.messages.len(), 0);

    let config = CONFIG.load(&deps.storage).unwrap();
    let new_owner_raw = deps.api.addr_validate(&new_owner).unwrap();
    assert_eq!(new_owner_raw, config.creator);

    // new owner can send the owner related messages
    let update_prams = UpdateParams {
        max_burn_ratio: Decimal::from_ratio(Uint128::new(10), Uint128::new(100)),
    };

    let new_owner_info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), new_owner_info, update_prams).unwrap();
    assert_eq!(res.messages.len(), 0);

    // previous owner cannot send this message
    let update_prams = UpdateParams {
        max_burn_ratio: Decimal::from_ratio(Uint128::new(10), Uint128::new(100)),
    };

    let new_owner_info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), new_owner_info, update_prams);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    let update_config = UpdateConfig {
        owner: None,
        rewards_dispatcher_contract: Some(String::from("new reward")),
        validators_registry_contract: None,
        statom_token_contract: None,
    };
    let new_owner_info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), new_owner_info, update_config).unwrap();
    assert_eq!(res.messages.len(), 1);

    let msg: CosmosMsg = CosmosMsg::Distribution(DistributionMsg::SetWithdrawAddress {
        address: String::from("new reward"),
    });
    assert_eq!(msg, res.messages[0].msg.clone());

    let config = Config {};
    let config_query: ConfigResponse =
        from_binary(&query(deps.as_ref(), mock_env(), config).unwrap()).unwrap();
    assert_eq!(
        config_query.reward_dispatcher_contract.unwrap(),
        String::from("new reward")
    );

    let config = Config {};
    let config_query: ConfigResponse =
        from_binary(&query(deps.as_ref(), mock_env(), config).unwrap()).unwrap();

    // make sure the other configs are still the same.
    assert_eq!(
        config_query.reward_dispatcher_contract.unwrap(),
        String::from("new reward")
    );
    assert_eq!(config_query.owner, new_owner);

    let update_config = UpdateConfig {
        owner: None,
        rewards_dispatcher_contract: None,
        validators_registry_contract: None,
        statom_token_contract: None,
    };
    let new_owner_info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), new_owner_info, update_config).unwrap();
    assert_eq!(res.messages.len(), 0);

    let update_config = UpdateConfig {
        owner: None,
        rewards_dispatcher_contract: None,
        validators_registry_contract: Some(String::from("new registry")),
        statom_token_contract: None,
    };
    let new_owner_info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), new_owner_info, update_config).unwrap();
    assert_eq!(res.messages.len(), 0);

    let config = Config {};
    let config_query: ConfigResponse =
        from_binary(&query(deps.as_ref(), mock_env(), config).unwrap()).unwrap();
    assert_eq!(
        config_query.validators_registry_contract.unwrap(),
        String::from("new registry"),
    );

    let update_config = UpdateConfig {
        owner: None,
        rewards_dispatcher_contract: None,
        validators_registry_contract: None,
        statom_token_contract: Some(statom_token_contract.clone()),
    };
    let new_owner_info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), new_owner_info, update_config);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("updating stAtom token address is forbidden",)
    );

    let config = Config {};
    let config_query: ConfigResponse =
        from_binary(&query(deps.as_ref(), mock_env(), config).unwrap()).unwrap();
    assert_eq!(
        config_query.statom_token_contract.unwrap(),
        statom_token_contract,
    );
}

fn set_delegation(querier: &mut WasmMockQuerier, validator: Validator, amount: u128, denom: &str) {
    querier.update_staking(
        "uatom",
        &[validator.clone()],
        &[sample_delegation(validator.address, coin(amount, denom))],
    );
}

fn set_custom_delegation(
    querier: &mut WasmMockQuerier,
    delegator: Addr,
    validator: Validator,
    amount: u128,
    denom: &str,
) {
    querier.update_staking(
        "uatom",
        &[validator.clone()],
        &[custom_delegation(
            delegator,
            validator.address,
            coin(amount, denom),
        )],
    );
}

fn set_delegation_query(
    querier: &mut WasmMockQuerier,
    delegate: &[FullDelegation],
    validators: &[Validator],
) {
    querier.update_staking("uatom", validators, delegate);
}

fn sample_delegation(addr: String, amount: Coin) -> FullDelegation {
    let can_redelegate = amount.clone();
    let accumulated_rewards = coins(0, &amount.denom);
    FullDelegation {
        validator: addr,
        delegator: Addr::unchecked(String::from(MOCK_CONTRACT_ADDR)),
        amount,
        can_redelegate,
        accumulated_rewards,
    }
}

fn custom_delegation(delegator: Addr, validator: String, amount: Coin) -> FullDelegation {
    let can_redelegate = amount.clone();
    let accumulated_rewards = coins(0, &amount.denom);
    FullDelegation {
        validator,
        delegator,
        amount,
        can_redelegate,
        accumulated_rewards,
    }
}

// sample MIR claim msg
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::upper_case_acronyms)]
pub enum MIRMsg {
    MIRClaim {},
}

#[test]
fn proper_redelegate_proxy() {
    let mut deps = dependencies(&[]);

    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");
    let validators_registry = String::from("validators_registry");

    initialize(
        deps.borrow_mut(),
        owner.clone(),
        reward_contract,
        statom_token_contract,
    );

    let redelegate_proxy_msg = ExecuteMsg::RedelegateProxy {
        src_validator: String::from("src_validator"),
        redelegations: vec![(String::from("dst_validator"), Coin::new(100, "uatom"))],
    };

    // invalid sender
    let info = mock_info(&addr1, &[]);
    let res = execute(
        deps.as_mut(),
        mock_env(),
        info,
        redelegate_proxy_msg.clone(),
    )
    .unwrap_err();
    assert_eq!(res, StdError::generic_err("unauthorized"));

    // check that validators_registry can send such messages
    let info = mock_info(&validators_registry, &[]);
    let res = execute(
        deps.as_mut(),
        mock_env(),
        info,
        redelegate_proxy_msg.clone(),
    )
    .unwrap();

    let redelegate = &res.messages[0];
    match redelegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Redelegate {
            src_validator,
            dst_validator,
            amount,
        }) => {
            assert_eq!(src_validator, String::from("src_validator"));
            assert_eq!(dst_validator, String::from("dst_validator"));
            assert_eq!(amount, Coin::new(100, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", redelegate),
    }

    // check that creator can send such messages
    let info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, redelegate_proxy_msg).unwrap();

    let redelegate = &res.messages[0];
    match redelegate.msg.clone() {
        CosmosMsg::Staking(StakingMsg::Redelegate {
            src_validator,
            dst_validator,
            amount,
        }) => {
            assert_eq!(src_validator, String::from("src_validator"));
            assert_eq!(dst_validator, String::from("dst_validator"));
            assert_eq!(amount, Coin::new(100, "uatom"));
        }
        _ => panic!("Unexpected message: {:?}", redelegate),
    }
}

///
#[test]
pub fn test_pause() {
    let mut deps = dependencies(&[]);

    let _validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    initialize(
        deps.borrow_mut(),
        owner.clone(),
        reward_contract,
        statom_token_contract,
    );

    let mut env = mock_env();

    // pause contract (we don't care about duration at this test step)
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 1u64 };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    execute(deps.as_mut(), env.clone(), creator_info, pause_contracts).unwrap();

    // try to run a not allowed action, should return an error
    let reward_msg = ExecuteMsg::DispatchRewards {};
    let info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), env.clone(), info, reward_msg);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("the contract is temporarily paused")
    );

    // un-pause the contract
    let unpause_contracts = ExecuteMsg::UnpauseContracts {};
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    execute(deps.as_mut(), env.clone(), creator_info, unpause_contracts).unwrap();

    // make sure another unpause doesn't mess things up
    let unpause_contracts = ExecuteMsg::UnpauseContracts {};
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    execute(deps.as_mut(), env.clone(), creator_info, unpause_contracts).unwrap();
    let params = Params {};
    let query_params: Parameters =
        from_binary(&query(deps.as_ref(), env.clone(), params).unwrap()).unwrap();
    assert_eq!(query_params.paused_until, None);

    // execute the same handler, should work
    let reward_msg = ExecuteMsg::DispatchRewards {};
    let info = mock_info(&owner, &[]);
    execute(deps.as_mut(), env.clone(), info, reward_msg).unwrap();

    // restricted to run pause with zero duration
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 0u64 };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), env.clone(), creator_info, pause_contracts);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("pause duration should be greater than zero")
    );

    // set paused for 50 blocks
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 50u64 };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), env.clone(), creator_info, pause_contracts).unwrap();
    assert_eq!(res.attributes[0].value, "pause_contracts");
    assert_eq!(res.attributes[1].value, "50");
    assert_eq!(res.attributes[2].value, "12395"); // mock_env height 12345 + 50

    // try to run an action during the pause, should return an error
    env.block.height += 40;
    let reward_msg = ExecuteMsg::DispatchRewards {};
    let info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), env.clone(), info, reward_msg);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("the contract is temporarily paused")
    );

    // try to pause contracts for a not greater period of time than they're already paused
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 5u64 }; // lesser duration
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), env.clone(), creator_info, pause_contracts);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("contracts are already paused for a greater or equal duration")
    );
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 10u64 }; // equal duration
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), env.clone(), creator_info, pause_contracts);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("contracts are already paused for a greater or equal duration")
    );

    // try to run an action after the pause, should work
    env.block.height += 11; // 12396
    let reward_msg = ExecuteMsg::DispatchRewards {};
    let info = mock_info(&owner, &[]);
    execute(deps.as_mut(), env.clone(), info, reward_msg).unwrap();

    // try to pause for a duration greater than MAX_PAUSE_DURATION results in an error
    let pause_contracts = ExecuteMsg::PauseContracts { duration: u64::MAX };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), env.clone(), creator_info, pause_contracts);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err(format!(
            "pause duration is too big: it's only possible to pause contracts for {} blocks or less",
            MAX_PAUSE_DURATION
        ),)
    );

    // pause and prolong the pause after a while
    let pause_contracts = ExecuteMsg::PauseContracts {
        duration: MAX_PAUSE_DURATION,
    };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), env.clone(), creator_info, pause_contracts).unwrap();
    assert_eq!(res.attributes[2].key, "pause_until");
    assert_eq!(
        res.attributes[2].value,
        format!("{}", 12396 + MAX_PAUSE_DURATION)
    );
    env.block.height += 50000;
    let pause_contracts = ExecuteMsg::PauseContracts {
        duration: MAX_PAUSE_DURATION,
    };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    let res = execute(deps.as_mut(), env, creator_info, pause_contracts).unwrap();
    assert_eq!(res.attributes[0].key, "action");
    assert_eq!(res.attributes[0].value, "pause_contracts");
    assert_eq!(res.attributes[1].key, "pause_for");
    assert_eq!(res.attributes[1].value, format!("{}", MAX_PAUSE_DURATION));
    assert_eq!(res.attributes[2].key, "pause_until");
    assert_eq!(
        res.attributes[2].value,
        format!("{}", 12396 + 50000 + MAX_PAUSE_DURATION)
    );
}

#[test]
pub fn test_guardians() {
    let mut deps = dependencies(&[]);

    let _validator = sample_validator(DEFAULT_VALIDATOR);
    set_validator_mock(&mut deps.querier);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    let guardian1 = String::from("guardian1");
    let guardian2 = String::from("guardian2");

    initialize(
        deps.borrow_mut(),
        owner.clone(),
        reward_contract,
        statom_token_contract,
    );

    // try to add guardians
    // must fail, because only the owner can add guardians
    let add_guardians = ExecuteMsg::AddGuardians {
        addresses: vec![guardian1.clone(), guardian2.clone()],
    };
    let creator_info = mock_info(String::from("some_user").as_str(), &[]);
    let res = execute(deps.as_mut(), mock_env(), creator_info, add_guardians);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    // add guardians
    let add_guardians = ExecuteMsg::AddGuardians {
        addresses: vec![guardian1.clone(), guardian2.clone()],
    };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    execute(deps.as_mut(), mock_env(), creator_info, add_guardians).unwrap();

    let query_guardians = QueryMsg::Guardians {
        start_after: None,
        limit: None,
    };
    let guardians: Vec<String> =
        from_binary(&query(deps.as_ref(), mock_env(), query_guardians).unwrap()).unwrap();
    assert_eq!(guardians.len(), 2);
    assert_eq!(guardians, vec![guardian1.clone(), guardian2.clone()]);

    let query_guardians = QueryMsg::Guardians {
        start_after: None,
        limit: Some(1),
    };
    let guardians: Vec<String> =
        from_binary(&query(deps.as_ref(), mock_env(), query_guardians).unwrap()).unwrap();
    assert_eq!(guardians.len(), 1);
    assert_eq!(guardians, vec![guardian1.clone()]);

    let query_guardians = QueryMsg::Guardians {
        start_after: Some(guardian1.clone()),
        limit: None,
    };
    let guardians: Vec<String> =
        from_binary(&query(deps.as_ref(), mock_env(), query_guardians).unwrap()).unwrap();
    assert_eq!(guardians.len(), 1);
    assert_eq!(guardians, vec![guardian2.clone()]);

    // set paused
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 1u64 };
    let guardian_info = mock_info(guardian1.as_str(), &[]);
    execute(deps.as_mut(), mock_env(), guardian_info, pause_contracts).unwrap();

    // try to run a not allowed action, should return an error
    let reward_msg = ExecuteMsg::DispatchRewards {};
    let info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, reward_msg);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("the contract is temporarily paused")
    );

    // guardians cannot unpause the contracts
    let unpause_contracts = ExecuteMsg::UnpauseContracts {};
    let creator_info = mock_info(guardian2.as_str(), &[]);
    let res = execute(deps.as_mut(), mock_env(), creator_info, unpause_contracts);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    // but the owner can
    let unpause_contracts = ExecuteMsg::UnpauseContracts {};
    let creator_info = mock_info(owner.as_str(), &[]);
    execute(deps.as_mut(), mock_env(), creator_info, unpause_contracts).unwrap();

    // check that contracts are unpaused
    let reward_msg = ExecuteMsg::DispatchRewards {};
    let info = mock_info(&owner, &[]);
    execute(deps.as_mut(), mock_env(), info, reward_msg).unwrap();

    // try to remove guardian
    // must fail, because only the owner can remove guardians
    let remove_guardian = ExecuteMsg::RemoveGuardians {
        addresses: vec![guardian1.clone()],
    };
    let creator_info = mock_info(guardian2.as_str(), &[]);
    let res = execute(deps.as_mut(), mock_env(), creator_info, remove_guardian);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    // remove guardian
    let remove_guardian = ExecuteMsg::RemoveGuardians {
        addresses: vec![guardian1.clone()],
    };
    let creator_info = mock_info(String::from("owner1").as_str(), &[]);
    execute(deps.as_mut(), mock_env(), creator_info, remove_guardian).unwrap();

    let query_guardians = QueryMsg::Guardians {
        start_after: None,
        limit: None,
    };
    let guardians: Vec<String> =
        from_binary(&query(deps.as_ref(), mock_env(), query_guardians).unwrap()).unwrap();
    assert_eq!(guardians.len(), 1);
    assert_eq!(guardians, vec![guardian2.clone()]);

    // removed guardian cannot pause the contracts
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 1u64 };
    let guardian_info = mock_info(guardian1.as_str(), &[]);
    let res = execute(deps.as_mut(), mock_env(), guardian_info, pause_contracts);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    // but the rest can
    let pause_contracts = ExecuteMsg::PauseContracts { duration: 1u64 };
    let guardian_info = mock_info(guardian2.as_str(), &[]);
    execute(deps.as_mut(), mock_env(), guardian_info, pause_contracts).unwrap();

    // try to run a not allowed action, should return an error
    let reward_msg = ExecuteMsg::DispatchRewards {};
    let info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, reward_msg);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("the contract is temporarily paused")
    );
}

#[test]
fn proper_receive_tokenized_share() {
    let mut deps = dependencies(&[]);
    let validator = sample_validator(DEFAULT_VALIDATOR);
    let validator2 = sample_validator(DEFAULT_VALIDATOR2);
    let validator3 = sample_validator(DEFAULT_VALIDATOR3);
    set_validator_mock(&mut deps.querier);

    let addr1 = String::from("addr1000");
    let module_account = String::from("module_address");
    let tokenize_shares_amount = Uint128::from(100u64);

    let owner = String::from("owner1");
    let statom_token_contract = String::from("statom_token");
    let reward_contract = String::from("reward");

    let share_denom = String::from("share_denom");
    let share_denom1 = String::from("share_denom1");
    let share_denom_with_not_whitelisted_validator =
        String::from("share_denom_with_not_whitelisted_validator");
    let share_denom_invalid = String::from("some_invalid_denom");

    initialize(
        deps.borrow_mut(),
        owner,
        reward_contract,
        statom_token_contract.clone(),
    );

    // register_validator
    do_register_validator(&mut deps, validator.clone());
    do_register_validator(&mut deps, validator2.clone());
    do_register_validator(&mut deps, validator3);

    // receive of share with not whitelisted validator
    do_register_tokenize_share_record(
        &mut deps,
        TokenizeShareRecord::new_tokenize_share(
            1,
            addr1.clone(),
            module_account.clone(),
            share_denom_with_not_whitelisted_validator.clone(),
            String::from("not_whitelisted_validator"),
        ),
    );

    let receive_tokenized_share_msg = ExecuteMsg::ReceiveTokenizedShare {};

    let info = mock_info(
        &addr1,
        &[coin(
            tokenize_shares_amount.u128(),
            share_denom_with_not_whitelisted_validator,
        )],
    );

    let res = execute(deps.as_mut(), mock_env(), info, receive_tokenized_share_msg);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err("Validator is not whitelisted")
    );

    // receive with invalid share denom
    let receive_tokenized_share_msg = ExecuteMsg::ReceiveTokenizedShare {};

    let info = mock_info(
        &addr1,
        &[coin(
            tokenize_shares_amount.u128(),
            String::from("some_invalid_denom"),
        )],
    );

    let res = execute(deps.as_mut(), mock_env(), info, receive_tokenized_share_msg);
    assert_eq!(
        res.unwrap_err(),
        StdError::generic_err(format!(
            "cannot find tokenize share record with denom {}",
            share_denom_invalid
        ))
    );

    // successful receive
    do_register_tokenize_share_record(
        &mut deps,
        TokenizeShareRecord::new_tokenize_share(
            2,
            addr1.clone(),
            module_account.clone(),
            share_denom.clone(),
            validator.address.clone(),
        ),
    );
    let module_address =
        Addr::unchecked(get_module_address(deps.as_ref(), module_account.clone()).unwrap());

    set_custom_delegation(
        &mut deps.querier,
        module_address.clone(),
        validator,
        tokenize_shares_amount.u128(),
        "uatom",
    );

    let receive_tokenized_share_msg = ExecuteMsg::ReceiveTokenizedShare {};

    let info = mock_info(
        &addr1,
        &[coin(tokenize_shares_amount.u128(), share_denom.clone())],
    );

    let res = execute(deps.as_mut(), mock_env(), info, receive_tokenized_share_msg).unwrap();
    assert_eq!(2, res.messages.len());

    let redeem = &res.messages[0];
    if redeem.msg.clone()
        != build_redeem_tokenize_share_msg(
            MOCK_CONTRACT_ADDR.to_string(),
            Coin::new(100, share_denom),
        )
        .unwrap()
    {
        panic!("Unexpected message: {:?}", redeem)
    }

    let mint = &res.messages[1];
    match mint.msg.clone() {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds: _,
        }) => {
            assert_eq!(contract_addr, statom_token_contract);
            assert_eq!(
                msg,
                to_binary(&Cw20ExecuteMsg::Mint {
                    recipient: addr1.clone(),
                    // We multiply by the ratio to adjust for the partial send of the tokens
                    // (user didn't send us the full amount of tokenized shares).
                    amount: tokenize_shares_amount
                        .multiply_ratio(tokenize_shares_amount, TOKENIZED_SHARES_SUPPLY),
                })
                .unwrap()
            )
        }
        _ => panic!("Unexpected message: {:?}", mint),
    }

    // successful receive with some slashing happened in delegation
    do_register_tokenize_share_record(
        &mut deps,
        TokenizeShareRecord::new_tokenize_share(
            3,
            addr1.clone(),
            module_account,
            share_denom1.clone(),
            validator2.address.clone(),
        ),
    );

    set_custom_delegation(
        &mut deps.querier,
        module_address,
        validator2,
        tokenize_shares_amount.u128() / 2, // validator was slashed for 50%
        "uatom",
    );

    let redeem_amount = 50u128;

    let receive_tokenized_share_msg = ExecuteMsg::ReceiveTokenizedShare {};

    let info = mock_info(&addr1, &[coin(redeem_amount, share_denom1.clone())]);

    deps.querier.with_native_balances(&[(
        addr1.clone(),
        coin(
            tokenize_shares_amount.u128() - redeem_amount,
            share_denom1.clone(),
        ),
    )]);

    let res = execute(deps.as_mut(), mock_env(), info, receive_tokenized_share_msg).unwrap();
    assert_eq!(2, res.messages.len());

    let redeem = &res.messages[0];
    if redeem.msg.clone()
        != build_redeem_tokenize_share_msg(
            MOCK_CONTRACT_ADDR.to_string(),
            Coin::new(redeem_amount, share_denom1),
        )
        .unwrap()
    {
        panic!("Unexpected message: {:?}", redeem)
    }

    let mint = &res.messages[1];
    match mint.msg.clone() {
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr,
            msg,
            funds: _,
        }) => {
            assert_eq!(contract_addr, statom_token_contract);
            assert_eq!(
                msg,
                to_binary(&Cw20ExecuteMsg::Mint {
                    recipient: addr1,
                    // We multiply by the ratio to adjust for the partial send of the tokens
                    // (user didn't send us the full amount of tokenized shares).
                    amount: Uint128::from(25u128)
                        .multiply_ratio(tokenize_shares_amount, TOKENIZED_SHARES_SUPPLY),
                })
                .unwrap()
            )
        }
        _ => panic!("Unexpected message: {:?}", mint),
    }
}

fn build_binary_tokenize_shares_message(
    delegator: &str,
    validator: &str,
    owner: &str,
    amount: &str,
    denom: &str,
) -> Binary {
    let mut proto_coin = ProtoCoin::new();
    proto_coin.set_amount(amount.to_string());
    proto_coin.set_denom(denom.to_string());

    let mut tokenize_msg = MsgTokenizeShares::new();
    tokenize_msg.set_delegator_address(delegator.to_string());
    tokenize_msg.set_validator_address(validator.to_string());
    tokenize_msg.set_tokenized_share_owner(owner.to_string());
    tokenize_msg.set_amount(proto_coin);

    Binary::from(tokenize_msg.write_to_bytes().unwrap())
}
