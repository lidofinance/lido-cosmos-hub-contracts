# Lido Terra Hub  <!-- omit in toc -->

**NOTE**: Reference documentation for this contract is available [here](https://lidofinance.github.io/terra-docs/contracts/hub).

The Hub contract acts as the central hub for all minted stAtom. Native Atom tokens received from users are delegated from here, and undelegations from stAtom unbond requests are also handled from this contract. Rewards generated from delegations are withdrawn to the Reward Dispatcher contract, later distributed to stAtom holders.
