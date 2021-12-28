# Lido Terra Hub  <!-- omit in toc -->

**NOTE**: Reference documentation for this contract is available [here](https://lidofinance.github.io/terra-docs/contracts/hub).

The Hub contract acts as the central hub for all minted stLuna. Native Luna tokens received from users are delegated from here, and undelegations from stLuna unbond requests are also handled from this contract. Rewards generated from delegations are withdrawn to the Reward Dispatcher contract, later distributed to stLuna holders.
