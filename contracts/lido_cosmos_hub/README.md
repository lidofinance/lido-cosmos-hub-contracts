# Lido Cosmos Hub  <!-- omit in toc -->

**NOTE**: Reference documentation for this contract is available [here](https://docs.cosmos.lido.fi/contracts/hub).

The Hub contract acts as the central hub for all minted stAtom. Native Atom tokens as well as tokenized shares received from users are delegated from here, and shares tokenizations from stAtom unbond requests are also handled from this contract. Rewards generated from delegations are withdrawn to the Rewards Dispatcher contract and then are re-delegated back to the validators pool.
