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

//! This integration test tries to run and call the generated wasm.
//! It depends on a Wasm build being available, which you can create with `cargo wasm`.
//! Then running `cargo integration-test` will validate we can properly call into that generated Wasm.
//!
//! You can easily convert unit tests to integration tests as follows:
//! 1. Copy them over verbatim
//! 2. Then change
//!      let mut deps = mock_dependencies(&[]);
//!    to
//!      let mut deps = mock_instance(WASM, &[]);
//! 3. If you access raw storage, where ever you see something like:
//!      deps.storage.get(CONFIG_KEY).expect("no data stored");
//!    replace it with:
//!      deps.with_storage(|store| {
//!          let data = store.get(CONFIG_KEY).expect("no data stored");
//!          //...
//!      });
//! 4. Anywhere you see query(&deps, ...) you must replace it with query(deps.as_mut(), ...)

use cosmwasm_std::testing::{mock_env, mock_info};
use cosmwasm_std::{coins, Api, Coin, Decimal, StdError, Uint128};

use crate::contract::{execute, instantiate};
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::CONFIG;
use crate::testing::mock_querier::{
    mock_dependencies, MOCK_HUB_CONTRACT_ADDR, MOCK_LIDO_FEE_ADDRESS,
};

fn default_init() -> InstantiateMsg {
    InstantiateMsg {
        hub_contract: String::from(MOCK_HUB_CONTRACT_ADDR),
        statom_reward_denom: "uatom".to_string(),
        lido_fee_address: String::from(MOCK_LIDO_FEE_ADDRESS),
        lido_fee_rate: Decimal::from_ratio(Uint128::from(5u64), Uint128::from(100u64)),
    }
}

#[test]
fn proper_initialization() {
    let mut deps = mock_dependencies(&[]);

    let msg = default_init();
    let info = mock_info("creator", &coins(1000, "earth"));

    // we can just call .unwrap() to assert this was a success
    let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());
}

#[test]
fn test_dispatch_rewards() {
    let mut deps = mock_dependencies(&[
        Coin::new(200, "uatom"),
        Coin::new(3200, "uusd"),
        Coin::new(6400, "usdr"),
    ]);

    let msg = default_init();
    let info = mock_info("creator", &[]);

    // we can just call .unwrap() to assert this was a success
    let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());

    let info = mock_info(String::from(MOCK_HUB_CONTRACT_ADDR).as_str(), &[]);
    let msg = ExecuteMsg::DispatchRewards {};

    let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
    assert_eq!(2, res.messages.len());
    for attr in res.attributes {
        if attr.key == "statom_rewards" {
            assert_eq!("190uatom", attr.value)
        }
        if attr.key == "lido_statom_fee" {
            assert_eq!("10uatom", attr.value)
        }
    }
}

#[test]
fn test_dispatch_rewards_zero_lido_fee() {
    let mut deps = mock_dependencies(&[Coin::new(200, "uatom"), Coin::new(320, "uusd")]);

    let msg = InstantiateMsg {
        hub_contract: String::from(MOCK_HUB_CONTRACT_ADDR),
        statom_reward_denom: "uatom".to_string(),
        lido_fee_address: String::from(MOCK_LIDO_FEE_ADDRESS),
        lido_fee_rate: Decimal::zero(),
    };
    let info = mock_info("creator", &[]);

    // we can just call .unwrap() to assert this was a success
    let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());

    let info = mock_info(String::from(MOCK_HUB_CONTRACT_ADDR).as_str(), &[]);
    let msg = ExecuteMsg::DispatchRewards {};

    let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
    assert_eq!(1, res.messages.len());

    for attr in res.attributes {
        if attr.key == "statom_rewards" {
            assert_eq!("200uatom", attr.value)
        }
    }
}

#[test]
fn test_update_config() {
    let mut deps = mock_dependencies(&[]);

    let owner = String::from("creator");
    let msg = default_init();
    let info = mock_info(&owner, &coins(1000, "earth"));

    // we can just call .unwrap() to assert this was a success
    let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());

    // check call from invalid owner
    let invalid_owner = String::from("invalid_owner");
    let update_config_msg = ExecuteMsg::UpdateConfig {
        owner: Some(String::from("some_addr")),
        hub_contract: None,
        statom_reward_denom: None,
        lido_fee_address: None,
        lido_fee_rate: None,
    };
    let info = mock_info(&invalid_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config_msg);
    assert_eq!(res.unwrap_err(), StdError::generic_err("unauthorized"));

    // change owner
    let new_owner = String::from("new_owner");
    let update_config_msg = ExecuteMsg::UpdateConfig {
        owner: Some(new_owner.clone()),
        hub_contract: None,
        statom_reward_denom: None,
        lido_fee_address: None,
        lido_fee_rate: None,
    };
    let info = mock_info(&owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config_msg);
    assert!(res.is_ok());

    let config = CONFIG.load(&deps.storage).unwrap();
    let new_owner_raw = deps.api.addr_validate(&new_owner).unwrap();
    assert_eq!(new_owner_raw, config.owner);

    // change hub_contract
    let update_config_msg = ExecuteMsg::UpdateConfig {
        owner: None,
        hub_contract: Some(String::from("some_address")),
        statom_reward_denom: None,
        lido_fee_address: None,
        lido_fee_rate: None,
    };
    let info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config_msg);
    assert!(res.is_ok());

    let config = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(
        deps.api
            .addr_validate(&String::from("some_address"))
            .unwrap(),
        config.hub_contract
    );

    // change statom_reward_denom
    let update_config_msg = ExecuteMsg::UpdateConfig {
        owner: None,
        hub_contract: None,
        statom_reward_denom: Some(String::from("new_denom")),
        lido_fee_address: None,
        lido_fee_rate: None,
    };
    let info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config_msg);
    assert!(res.is_err());
    assert_eq!(
        Some(StdError::generic_err(
            "updating statom reward denom is forbidden"
        )),
        res.err()
    );

    let config = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(String::from("uatom"), config.statom_reward_denom);

    // change lido_fee_address
    let update_config_msg = ExecuteMsg::UpdateConfig {
        owner: None,
        hub_contract: None,
        statom_reward_denom: None,
        lido_fee_address: Some(String::from("some_address")),
        lido_fee_rate: None,
    };
    let info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config_msg);
    assert!(res.is_ok());

    let config = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(
        deps.api
            .addr_validate(&String::from("some_address"))
            .unwrap(),
        config.lido_fee_address
    );

    // change lido_fee_rate
    let update_config_msg = ExecuteMsg::UpdateConfig {
        owner: None,
        hub_contract: None,
        statom_reward_denom: None,
        lido_fee_address: None,
        lido_fee_rate: Some(Decimal::one()),
    };
    let info = mock_info(&new_owner, &[]);
    let res = execute(deps.as_mut(), mock_env(), info, update_config_msg);
    assert!(res.is_ok());

    let config = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(Decimal::one(), config.lido_fee_rate);
}
