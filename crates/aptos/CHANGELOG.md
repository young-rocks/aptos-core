# Aptos CLI Changelog

All notable changes to the Aptos CLI will be captured in this file. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and the format set out by [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

## [2.3.2] - 2023/11/28
- Services in the local testnet now bind to 127.0.0.1 by default (unless the CLI is running inside a container, which most users should not do) rather than 0.0.0.0. You can override this behavior with the `--bind-to` flag. This fixes an issue preventing the local testnet from working on Windows.

## [2.3.1] - 2023/11/07
### Updated
- Updated processor code from https://github.com/aptos-labs/aptos-indexer-processors for the local testnet to 2d5cb211a89a8705674e9e1e741c841dd899c558. 
- Improved reliability of inter-container networking with local testnet.

## [2.3.0] - 2023/10/25
### Added
- Added `--node-api-key`. This lets you set an API key for the purpose of not being ratelimited.

### Updated
- Made the local testnet exit more quickly if a service fails to start.
- Updated processor code from https://github.com/aptos-labs/aptos-indexer-processors for the local testnet to bcba94c26c8a6372056d2b69ce411c5719f98965.

### Fixed
- Fixed an infrequent bug that caused startup failures for the local testnet with `--force-restart` + `--with-indexer-api` by using a Docker volume rather than a bind mount for the postgres storage.
- Fixed an issue where the CLI could not find the Docker socket with some Docker Desktop configurations.

## [2.2.2] - 2023/10/16
### Updated
- Updated processor code from https://github.com/aptos-labs/aptos-indexer-processors for the local testnet to d6f55d4baba32960ea7be60878552e73ffbe8b7e.

## [2.2.1] - 2023/10/13
### Fixed
- Fixed postgres data persistence between restarts when using `aptos node run-local-testnet --with-indexer-api`.

## [2.2.0] - 2023/10/11
### Added
- Added `--with-indexer-api` to `aptos node run-local-testnet`. With this flag you can run a full processor + indexer API stack as part of your local testnet. You must have Docker installed to use this feature. For more information, see https://aptos.dev/nodes/local-testnet/local-testnet-index.
### Updated
- Updated CLI source compilation to use rust toolchain version 1.72.1 (from 1.71.1).

## [2.1.1] - 2023/09/27
### Added
- Added an option `--print-metadata` to the command `aptos move download` to print out the metadata of the package to be downloaded.
  - Example: `aptos move download  --account 0x1 --package AptosFramework --url https://mainnet.aptoslabs.com/v1 --print-metadata`
### Updated
- The `--with-faucet` flag has been removed from `aptos node run-local-testnet`, we now run a faucet by default. To disable the faucet use the `--no-faucet` flag.
- **Breaking change**: When using `aptos node run-local-testnet` we now expose a transaction stream. Learn more about the transaction stream service here: https://aptos.dev/indexer/txn-stream/. Opt out of this with `--no-txn-stream`. This is marked as a breaking change since the CLI now uses a port (50051 by default) that it didn't used to. If you need this port, you can tell the CLI to use a different port with `--txn-stream-port`.

## [2.1.0] - 2023/08/24
### Updated
- Updated CLI source compilation to use rust toolchain version 1.71.1 (from 1.71.0).
### Added
- Added basic ledger support for CLI
  - Example: `aptos init --ledger` to create a new profile from ledger. After this, you can use it the same way as other profiles.
  - Note: `Ledger Nano s Plus` or `Ledger Nano X` is highly recommended.

## [2.0.3] - 2023/08/04
### Fixed
- Fixed the following input arguments issue when running `aptos move view`
  - #8513: Fixed issue where CLI does not work with big numbers
  - #8982: Fixed args issue when passing in u64/u128/u256 parameters
### Update
- CLI documentation refactor
- Updated CLI source compilation to use rust toolchain version 1.71.0 (from 1.70.0).
### Fixed
* Verify package now does not fail on a mismatched upgrade number

## [2.0.2] - 2023/07/06
### Added
- Added account lookup by authentication key
  - Example: `account lookup-address --auth-key {your_auth_key}`
### Updated
- Updated CLI source compilation to use rust toolchain version 1.70.0 (from 1.66.1).
- Set 2 seconds timeout for telemetry
### Removed
- init command from config subcommand is removed. Please use init from the root command.
  - Example: `aptos config init` -> `aptos init`
### Fixed
- Panic issue when running `aptos move test` is fixed - GitHub issue #8516

## [2.0.1] - 2023/06/05
### Fixed
- Updated txn expiration configuration for the faucet built into the CLI to make local testnet startup more reliable.

## [2.0.0] - 2023/06/01
### Added
- Multisig v2 governance support
- JSON input file support
- Builder Pattern support for RestClient
  - NOTE: Methods **new_with_timeout** and **new_with_timeout_and_user_agent** are no longer available.
- Added custom header *x-aptos-client* for analytic purpose

## [1.0.14] - 2023/05/26
- Updated DB bootstrap command with new DB restore features
- Nested vector arg support
    - **Breaking change**: You can no longer pass in a vector like this: `--arg vector<address>:0x1,0x2`, you must do it like this: `--arg 'address:["0x1", "0x2"]'`

## [1.0.13] - 2023/04/27
### Fixed
* Previously `--skip-fetch-latest-git-deps` would not actually do anything when used with `aptos move test`. This has been fixed.
* Fixed the issue of the hello_blockchain example where feature enable was missing

## [1.0.12] - 2023/04/25
### Added
* Support for creating and interacting with multisig accounts v2. More details can be found at [AIP 12](https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-12.md).
* Added `disassemble` option to the CLI - This can be invoked using `aptos move disassemble` to disassemble the bytecode and save it to a file
* Fixed handling of `vector<string>` as an entry function argument in `aptos move run`

## [1.0.11] - 2023/04/14
### Fixed
* Fixed creating a new test account with `aptos init` would fail if the account didn't already exist

## [1.0.10] - 2023/04/13
### Fixed
* If `aptos init` is run with a faucet URL specified (which happens by default when using the local, devnet, or testnet network options) and funding the account fails, the account creation is considered a failure and nothing is persisted. Previously it would report success despite the account not being created on chain.
* When specifying a profile where the `AuthenticationKey` has been rotated, now the `AccountAddress` is properly used from the config file
* Update `aptos init` to fix an incorrect account address issue, when trying to init with a rotated private key. Right now it does an actual account lookup instead of deriving from public key

### Added
* Updates to prover and framework specs

## [1.0.9] - 2023/03/29
### Added
* `aptos move show abi` allows for viewing the ABI of a compiled move package
* Experimental gas profiler with the `--profile-gas` flag on any transaction submitting CLI command
* Updates to the prover and framework specs

## [1.0.8] - 2023/03/16
### Added
* Added an `aptos account derive-resource-account-address` command to add the ability to derive an address easily
* Added the ability for different input resource account seeds, to allow matching directly with onchain code
* Added beta support for coverage via `aptos move coverage` and `aptos move test --coverage`
* Added beta support for compiling with bytecode dependencies rather than source dependencies

### Fixed
* All resource account commands can now use `string_seed` which will match the onchain representation of `b"string"` rather than always derive a different address
* Tests that go over the bytecode size limit can now compile
* `vector<string>` inputs to now work for both `aptos move view` and `aptos move run`
* Governance proposal listing will now not crash on the latest on-chain format
* Move compiler will no longer use an environment variable to communicate between compiler and CLI for the bytecode version

## [1.0.7]
* For logs earlier than 1.0.7, please check out the [releases on GitHub](https://github.com/aptos-labs/aptos-core/releases?q="Aptos+CLI+Release")
