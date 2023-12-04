// Copyright © Aptos Foundation
// Parts of the project are originally copyright © Meta Platforms, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    aptos_vm_impl::{get_transaction_output, AptosVMImpl},
    block_executor::{AptosTransactionOutput, BlockAptosVM},
    counters::*,
    data_cache::{AsMoveResolver, StorageAdapter},
    errors::expect_only_successful_execution,
    move_vm_ext::{
        get_max_binary_format_version, AptosMoveResolver, RespawnedSession, SessionExt, SessionId,
    },
    sharded_block_executor::{executor_client::ExecutorClient, ShardedBlockExecutor},
    system_module_names::*,
    transaction_metadata::TransactionMetadata,
    verifier, VMExecutor, VMValidator,
};
use anyhow::{anyhow, Result};
use aptos_block_executor::txn_commit_hook::NoOpTransactionCommitHook;
use aptos_crypto::HashValue;
use aptos_framework::natives::code::PublishRequest;
use aptos_gas_algebra::Gas;
use aptos_gas_meter::{AptosGasMeter, GasAlgebra, StandardGasAlgebra, StandardGasMeter};
use aptos_gas_schedule::VMGasParameters;
use aptos_logger::{enabled, prelude::*, Level};
use aptos_memory_usage_tracker::MemoryTrackedGasMeter;
use aptos_state_view::StateView;
use aptos_types::{
    account_config,
    account_config::new_block_event_key,
    block_executor::{
        config::{BlockExecutorConfig, BlockExecutorConfigFromOnchain, BlockExecutorLocalConfig},
        partitioner::PartitionedTransactions,
    },
    block_metadata::BlockMetadata,
    fee_statement::FeeStatement,
    on_chain_config::{new_epoch_event_key, FeatureFlag, TimedFeatureOverride},
    transaction::{
        signature_verified_transaction::SignatureVerifiedTransaction,
        EntryFunction, ExecutionError, ExecutionStatus, ModuleBundle, Multisig,
        MultisigTransactionPayload, SignatureCheckedTransaction, SignedTransaction, Transaction,
        Transaction::{
            BlockMetadata as BlockMetadataTransaction, GenesisTransaction, StateCheckpoint,
            UserTransaction,
        },
        TransactionOutput, TransactionPayload, TransactionStatus, VMValidatorResult,
        WriteSetPayload,
    },
    validator_txn::ValidatorTransaction,
    vm_status::{AbortLocation, StatusCode, VMStatus},
};
use aptos_utils::{aptos_try, return_on_failure};
use aptos_vm_logging::{log_schema::AdapterLogSchema, speculative_error, speculative_log};
use aptos_vm_types::{
    change_set::VMChangeSet,
    output::VMOutput,
    resolver::{ExecutorView, ResourceGroupView},
    storage::{ChangeSetConfigs, StorageGasParameters},
};
use claims::assert_err;
use fail::fail_point;
use move_binary_format::{
    access::ModuleAccess,
    compatibility::Compatibility,
    deserializer::DeserializerConfig,
    errors::{verification_error, Location, PartialVMError, VMError, VMResult},
    file_format_common::{IDENTIFIER_SIZE_MAX, LEGACY_IDENTIFIER_SIZE_MAX},
    CompiledModule, IndexKind,
};
use move_core_types::{
    account_address::AccountAddress,
    ident_str,
    identifier::Identifier,
    language_storage::{ModuleId, TypeTag},
    transaction_argument::convert_txn_args,
    value::{serialize_values, MoveValue},
    vm_status::StatusType,
};
use move_vm_runtime::session::SerializedReturnValues;
use move_vm_types::gas::UnmeteredGasMeter;
use num_cpus;
use once_cell::sync::{Lazy, OnceCell};
use std::{
    cmp::{max, min},
    collections::{BTreeMap, BTreeSet},
    marker::Sync,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

static EXECUTION_CONCURRENCY_LEVEL: OnceCell<usize> = OnceCell::new();
static NUM_EXECUTION_SHARD: OnceCell<usize> = OnceCell::new();
static NUM_PROOF_READING_THREADS: OnceCell<usize> = OnceCell::new();
static PARANOID_TYPE_CHECKS: OnceCell<bool> = OnceCell::new();
static PROCESSED_TRANSACTIONS_DETAILED_COUNTERS: OnceCell<bool> = OnceCell::new();
static TIMED_FEATURE_OVERRIDE: OnceCell<TimedFeatureOverride> = OnceCell::new();

// TODO: Don't expose this in AptosVM, and use only in BlockAptosVM!
pub static RAYON_EXEC_POOL: Lazy<Arc<rayon::ThreadPool>> = Lazy::new(|| {
    Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .thread_name(|index| format!("par_exec-{}", index))
            .build()
            .unwrap(),
    )
});

/// Remove this once the bundle is removed from the code.
static MODULE_BUNDLE_DISALLOWED: AtomicBool = AtomicBool::new(true);
pub fn allow_module_bundle_for_test() {
    MODULE_BUNDLE_DISALLOWED.store(false, Ordering::Relaxed);
}

pub struct AptosVM {
    is_simulation: bool,
    // TODO: Remove implementation and move it to this file.
    pub(crate) vm_impl: AptosVMImpl,
}

macro_rules! unwrap_or_discard {
    ($res:expr) => {
        match $res {
            Ok(s) => s,
            Err(e) => return discard_error_vm_status(e),
        }
    };
}

pub(crate) fn discard_error_vm_status(vm_status: VMStatus) -> (VMStatus, VMOutput) {
    let vm_output =
        VMOutput::empty_with_status(TransactionStatus::Discard(vm_status.status_code()));
    (vm_status, vm_output)
}

impl AptosVM {
    pub fn new(resolver: &impl AptosMoveResolver) -> Self {
        Self {
            is_simulation: false,
            vm_impl: AptosVMImpl::new(resolver),
        }
    }

    /// Sets execution concurrency level when invoked the first time.
    pub fn set_concurrency_level_once(mut concurrency_level: usize) {
        concurrency_level = min(concurrency_level, num_cpus::get());
        // Only the first call succeeds, due to OnceCell semantics.
        EXECUTION_CONCURRENCY_LEVEL.set(concurrency_level).ok();
    }

    /// Get the concurrency level if already set, otherwise return default 1
    /// (sequential execution).
    ///
    /// The concurrency level is fixed to 1 if gas profiling is enabled.
    pub fn get_concurrency_level() -> usize {
        match EXECUTION_CONCURRENCY_LEVEL.get() {
            Some(concurrency_level) => *concurrency_level,
            None => 1,
        }
    }

    pub fn set_num_shards_once(mut num_shards: usize) {
        num_shards = max(num_shards, 1);
        // Only the first call succeeds, due to OnceCell semantics.
        NUM_EXECUTION_SHARD.set(num_shards).ok();
    }

    pub fn get_num_shards() -> usize {
        match NUM_EXECUTION_SHARD.get() {
            Some(num_shards) => *num_shards,
            None => 1,
        }
    }

    /// Sets runtime config when invoked the first time.
    pub fn set_paranoid_type_checks(enable: bool) {
        // Only the first call succeeds, due to OnceCell semantics.
        PARANOID_TYPE_CHECKS.set(enable).ok();
    }

    /// Get the paranoid type check flag if already set, otherwise return default true
    pub fn get_paranoid_checks() -> bool {
        match PARANOID_TYPE_CHECKS.get() {
            Some(enable) => *enable,
            None => true,
        }
    }

    // Set the override profile for timed features.
    pub fn set_timed_feature_override(profile: TimedFeatureOverride) {
        TIMED_FEATURE_OVERRIDE.set(profile).ok();
    }

    pub fn get_timed_feature_override() -> Option<TimedFeatureOverride> {
        TIMED_FEATURE_OVERRIDE.get().cloned()
    }

    /// Sets the # of async proof reading threads.
    pub fn set_num_proof_reading_threads_once(mut num_threads: usize) {
        // TODO(grao): Do more analysis to tune this magic number.
        num_threads = min(num_threads, 256);
        // Only the first call succeeds, due to OnceCell semantics.
        NUM_PROOF_READING_THREADS.set(num_threads).ok();
    }

    /// Returns the # of async proof reading threads if already set, otherwise return default value
    /// (32).
    pub fn get_num_proof_reading_threads() -> usize {
        match NUM_PROOF_READING_THREADS.get() {
            Some(num_threads) => *num_threads,
            None => 32,
        }
    }

    /// Sets additional details in counters when invoked the first time.
    pub fn set_processed_transactions_detailed_counters() {
        // Only the first call succeeds, due to OnceCell semantics.
        PROCESSED_TRANSACTIONS_DETAILED_COUNTERS.set(true).ok();
    }

    /// Get whether we should capture additional details in counters
    pub fn get_processed_transactions_detailed_counters() -> bool {
        match PROCESSED_TRANSACTIONS_DETAILED_COUNTERS.get() {
            Some(value) => *value,
            None => false,
        }
    }

    /// Returns the internal gas schedule if it has been loaded, or an error if it hasn't.
    #[cfg(any(test, feature = "testing"))]
    pub fn gas_params(&self) -> Result<&aptos_gas_schedule::AptosGasParameters, VMStatus> {
        let log_context = AdapterLogSchema::new(aptos_state_view::StateViewId::Miscellaneous, 0);
        self.vm_impl.get_gas_parameters(&log_context)
    }

    /// Generates a transaction output for a transaction that encountered errors during the
    /// execution process. This is public for now only for tests.
    pub fn failed_transaction_cleanup(
        &self,
        error_code: VMStatus,
        gas_meter: &impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        resolver: &impl AptosMoveResolver,
        log_context: &AdapterLogSchema,
        change_set_configs: &ChangeSetConfigs,
    ) -> VMOutput {
        self.failed_transaction_cleanup_and_keep_vm_status(
            error_code,
            gas_meter,
            txn_data,
            resolver,
            log_context,
            change_set_configs,
        )
        .1
    }

    pub fn as_move_resolver<'r, R: ExecutorView>(
        &self,
        executor_view: &'r R,
    ) -> StorageAdapter<'r, R> {
        StorageAdapter::new_with_config(
            executor_view,
            self.vm_impl.get_gas_feature_version(),
            self.vm_impl.get_features(),
            None,
        )
    }

    pub fn as_move_resolver_with_group_view<'r, R: ExecutorView + ResourceGroupView>(
        &self,
        executor_view: &'r R,
    ) -> StorageAdapter<'r, R> {
        StorageAdapter::new_with_config(
            executor_view,
            self.vm_impl.get_gas_feature_version(),
            self.vm_impl.get_features(),
            Some(executor_view),
        )
    }

    fn fee_statement_from_gas_meter(
        txn_data: &TransactionMetadata,
        gas_meter: &impl AptosGasMeter,
        storage_fee_refund: u64,
    ) -> FeeStatement {
        let gas_used = txn_data
            .max_gas_amount()
            .checked_sub(gas_meter.balance())
            .expect("Balance should always be less than or equal to max gas amount");
        FeeStatement::new(
            gas_used.into(),
            u64::from(gas_meter.execution_gas_used()),
            u64::from(gas_meter.io_gas_used()),
            u64::from(gas_meter.storage_fee_used()),
            storage_fee_refund,
        )
    }

    fn failed_transaction_cleanup_and_keep_vm_status(
        &self,
        error_code: VMStatus,
        gas_meter: &impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        resolver: &impl AptosMoveResolver,
        log_context: &AdapterLogSchema,
        change_set_configs: &ChangeSetConfigs,
    ) -> (VMStatus, VMOutput) {
        if self.vm_impl.get_gas_feature_version() >= 12 {
            // Check if the gas meter's internal counters are consistent.
            //
            // Since we are already in the failure epilogue, there is not much we can do
            // other than logging the inconsistency.
            //
            // This is a tradeoff. We have to either
            //   1. Continue to calculate the gas cost based on the numbers we have.
            //   2. Discard the transaction.
            //
            // Option (2) does not work, since it would enable DoS attacks.
            // Option (1) is not ideal, but optimistically, it should allow the network
            // to continue functioning, less the transactions that run into this problem.
            if let Err(err) = gas_meter.algebra().check_consistency() {
                println!(
                    "[aptos-vm][gas-meter][failure-epilogue] {}",
                    err.message()
                        .unwrap_or("No message found -- this should not happen.")
                );
            }
        }

        // Clear side effects: create new session and clear refunds from fee statement.
        let mut session = self
            .vm_impl
            .new_session(resolver, SessionId::epilogue_meta(txn_data));
        let fee_statement = AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, 0);

        match TransactionStatus::from_vm_status(
            error_code.clone(),
            self.vm_impl
                .get_features()
                .is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION),
        ) {
            TransactionStatus::Keep(status) => {
                // Inject abort info if available.
                let status = match status {
                    ExecutionStatus::MoveAbort {
                        location: AbortLocation::Module(module),
                        code,
                        ..
                    } => {
                        let info = self.vm_impl.extract_abort_info(&module, code);
                        ExecutionStatus::MoveAbort {
                            location: AbortLocation::Module(module),
                            code,
                            info,
                        }
                    },
                    _ => status,
                };
                // The transaction should be charged for gas, so run the epilogue to do that.
                // This is running in a new session that drops any side effects from the
                // attempted transaction (e.g., spending funds that were needed to pay for gas),
                // so even if the previous failure occurred while running the epilogue, it
                // should not fail now. If it somehow fails here, there is no choice but to
                // discard the transaction.
                if let Err(e) = self.vm_impl.run_failure_epilogue(
                    &mut session,
                    gas_meter.balance(),
                    fee_statement,
                    txn_data,
                    log_context,
                ) {
                    return discard_error_vm_status(e);
                }
                let txn_output =
                    get_transaction_output(session, fee_statement, status, change_set_configs)
                        .unwrap_or_else(|e| discard_error_vm_status(e).1);
                (error_code, txn_output)
            },
            TransactionStatus::Discard(status) => {
                discard_error_vm_status(VMStatus::error(status, None))
            },
            TransactionStatus::Retry => unreachable!(),
        }
    }

    fn success_transaction_cleanup(
        &self,
        mut respawned_session: RespawnedSession,
        gas_meter: &impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        if self.vm_impl.get_gas_feature_version() >= 12 {
            // Check if the gas meter's internal counters are consistent.
            //
            // It's better to fail the transaction due to invariant violation than to allow
            // potentially bogus states to be committed.
            if let Err(err) = gas_meter.algebra().check_consistency() {
                println!(
                    "[aptos-vm][gas-meter][success-epilogue] {}",
                    err.message()
                        .unwrap_or("No message found -- this should not happen.")
                );
                return Err(err.finish(Location::Undefined).into());
            }
        }

        let fee_statement = AptosVM::fee_statement_from_gas_meter(
            txn_data,
            gas_meter,
            u64::from(respawned_session.get_storage_fee_refund()),
        );
        respawned_session.execute(|session| {
            self.vm_impl.run_success_epilogue(
                session,
                gas_meter.balance(),
                fee_statement,
                txn_data,
                log_context,
            )
        })?;
        let change_set = respawned_session.finish(change_set_configs)?;
        let output = VMOutput::new(
            change_set,
            fee_statement,
            TransactionStatus::Keep(ExecutionStatus::Success),
        );

        Ok((VMStatus::Executed, output))
    }

    fn validate_and_execute_entry_function(
        &self,
        session: &mut SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        senders: Vec<AccountAddress>,
        script_fn: &EntryFunction,
    ) -> Result<SerializedReturnValues, VMStatus> {
        let function = session.load_function(
            script_fn.module(),
            script_fn.function(),
            script_fn.ty_args(),
        )?;
        let struct_constructors = self
            .vm_impl
            .get_features()
            .is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS);
        let args = verifier::transaction_arg_validation::validate_combine_signer_and_txn_args(
            session,
            senders,
            script_fn.args().to_vec(),
            &function,
            struct_constructors,
        )?;
        Ok(session.execute_entry_function(
            script_fn.module(),
            script_fn.function(),
            script_fn.ty_args().to_vec(),
            args,
            gas_meter,
        )?)
    }

    fn execute_script_or_entry_function(
        &self,
        resolver: &impl AptosMoveResolver,
        mut session: SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        payload: &TransactionPayload,
        log_context: &AdapterLogSchema,
        new_published_modules_loaded: &mut bool,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        fail_point!("move_adapter::execute_script_or_entry_function", |_| {
            Err(VMStatus::Error {
                status_code: StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                sub_status: Some(move_core_types::vm_status::sub_status::unknown_invariant_violation::EPARANOID_FAILURE),
                message: None,
            })
        });

        // Run the execution logic
        {
            gas_meter.charge_intrinsic_gas_for_transaction(txn_data.transaction_size())?;

            match payload {
                TransactionPayload::Script(script) => {
                    let loaded_func =
                        session.load_script(script.code(), script.ty_args().to_vec())?;
                    // Gerardo: consolidate the extended validation to verifier.
                    verifier::event_validation::verify_no_event_emission_in_script(
                        script.code(),
                        &session.get_vm_config().deserializer_config,
                    )?;

                    let args =
                        verifier::transaction_arg_validation::validate_combine_signer_and_txn_args(
                            &mut session,
                            txn_data.senders(),
                            convert_txn_args(script.args()),
                            &loaded_func,
                            self.vm_impl
                                .get_features()
                                .is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS),
                        )?;
                    session.execute_script(
                        script.code(),
                        script.ty_args().to_vec(),
                        args,
                        gas_meter,
                    )?;
                },
                TransactionPayload::EntryFunction(script_fn) => {
                    self.validate_and_execute_entry_function(
                        &mut session,
                        gas_meter,
                        txn_data.senders(),
                        script_fn,
                    )?;
                },

                // Not reachable as this function should only be invoked for entry or script
                // transaction payload.
                _ => {
                    return Err(VMStatus::error(StatusCode::UNREACHABLE, None));
                },
            };

            self.resolve_pending_code_publish(
                &mut session,
                gas_meter,
                new_published_modules_loaded,
            )?;

            let respawned_session = self.charge_change_set_and_respawn_session(
                session,
                resolver,
                gas_meter,
                change_set_configs,
                txn_data,
            )?;

            self.success_transaction_cleanup(
                respawned_session,
                gas_meter,
                txn_data,
                log_context,
                change_set_configs,
            )
        }
    }

    fn charge_change_set_and_respawn_session<'r, 'l>(
        &'l self,
        session: SessionExt,
        resolver: &'r impl AptosMoveResolver,
        gas_meter: &mut impl AptosGasMeter,
        change_set_configs: &ChangeSetConfigs,
        txn_data: &TransactionMetadata,
    ) -> Result<RespawnedSession<'r, 'l>, VMStatus> {
        let mut change_set = session.finish(change_set_configs)?;

        for (key, op) in change_set.write_set_iter() {
            gas_meter.charge_io_gas_for_write(key, op)?;
        }
        // TODO[agg_v2](fix): Charge SnapshotDerived (string concat) based on length,
        // as charge below charges based on non-exchanged writes (i.e. identifier being in the read_op)
        // Do we want to charge delayed field changes also?
        for (key, (read_op, _)) in change_set.reads_needing_delayed_field_exchange().iter() {
            gas_meter.charge_io_gas_for_write(key, read_op)?;
        }
        for (key, group_write) in change_set.resource_group_write_set().iter() {
            gas_meter.charge_io_gas_for_group_write(
                key,
                &group_write.metadata_op,
                group_write.maybe_group_op_size(),
            )?;
        }
        for (key, (metadata_op, group_size)) in change_set
            .group_reads_needing_delayed_field_exchange()
            .iter()
        {
            gas_meter.charge_io_gas_for_group_write(key, metadata_op, Some(*group_size))?;
        }

        let mut storage_refund = gas_meter.process_storage_fee_for_all(
            &mut change_set,
            txn_data.transaction_size,
            txn_data.gas_unit_price,
        )?;
        if !self
            .vm_impl
            .get_features()
            .is_storage_deletion_refund_enabled()
        {
            storage_refund = 0.into();
        }

        // TODO[agg_v1](fix): Charge for aggregator writes
        let session_id = SessionId::epilogue_meta(txn_data);
        RespawnedSession::spawn(self, session_id, resolver, change_set, storage_refund)
    }

    fn simulate_multisig_transaction(
        &self,
        multisig: &Multisig,
        mut session: SessionExt,
        resolver: &impl AptosMoveResolver,
        txn_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
        gas_meter: &mut impl AptosGasMeter,
        new_published_modules_loaded: &mut bool,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        match &multisig.transaction_payload {
            None => Err(VMStatus::error(StatusCode::MISSING_DATA, None)),
            Some(multisig_payload) => {
                match multisig_payload {
                    MultisigTransactionPayload::EntryFunction(entry_function) => {
                        aptos_try!({
                            return_on_failure!(self.execute_multisig_entry_function(
                                &mut session,
                                gas_meter,
                                multisig.multisig_address,
                                entry_function,
                                new_published_modules_loaded,
                            ));
                            // TODO: Deduplicate this against execute_multisig_transaction
                            // A bit tricky since we need to skip success/failure cleanups,
                            // which is in the middle. Introducing a boolean would make the code
                            // messier.
                            let respawned_session = self.charge_change_set_and_respawn_session(
                                session,
                                resolver,
                                gas_meter,
                                change_set_configs,
                                txn_data,
                            )?;

                            self.success_transaction_cleanup(
                                respawned_session,
                                gas_meter,
                                txn_data,
                                log_context,
                                change_set_configs,
                            )
                        })
                    },
                }
            },
        }
    }

    // Execute a multisig transaction:
    // 1. Obtain the payload of the transaction to execute. This could have been stored on chain
    // when the multisig transaction was created.
    // 2. Execute the target payload. If this fails, discard the session and keep the gas meter and
    // failure object. In case of success, keep the session and also do any necessary module publish
    // cleanup.
    // 3. Call post transaction cleanup function in multisig account module with the result from (2)
    fn execute_multisig_transaction(
        &self,
        resolver: &impl AptosMoveResolver,
        mut session: SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        txn_payload: &Multisig,
        log_context: &AdapterLogSchema,
        new_published_modules_loaded: &mut bool,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        fail_point!("move_adapter::execute_multisig_transaction", |_| {
            Err(VMStatus::error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                None,
            ))
        });

        gas_meter.charge_intrinsic_gas_for_transaction(txn_data.transaction_size())?;

        // Step 1: Obtain the payload. If any errors happen here, the entire transaction should fail
        let invariant_violation_error = || {
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("MultiSig transaction error".to_string())
                .finish(Location::Undefined)
        };
        let provided_payload = if let Some(payload) = &txn_payload.transaction_payload {
            bcs::to_bytes(&payload).map_err(|_| invariant_violation_error())?
        } else {
            // Default to empty bytes if payload is not provided.
            bcs::to_bytes::<Vec<u8>>(&vec![]).map_err(|_| invariant_violation_error())?
        };
        // Failures here will be propagated back.
        let payload_bytes: Vec<Vec<u8>> = session
            .execute_function_bypass_visibility(
                &MULTISIG_ACCOUNT_MODULE,
                GET_NEXT_TRANSACTION_PAYLOAD,
                vec![],
                serialize_values(&vec![
                    MoveValue::Address(txn_payload.multisig_address),
                    MoveValue::vector_u8(provided_payload),
                ]),
                gas_meter,
            )?
            .return_values
            .into_iter()
            .map(|(bytes, _ty)| bytes)
            .collect::<Vec<_>>();
        let payload_bytes = payload_bytes
            .first()
            // We expect the payload to either exists on chain or be passed along with the
            // transaction.
            .ok_or_else(|| {
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Multisig payload bytes return error".to_string())
                    .finish(Location::Undefined)
            })?;
        // We have to deserialize twice as the first time returns the actual return type of the
        // function, which is vec<u8>. The second time deserializes it into the correct
        // EntryFunction payload type.
        // If either deserialization fails for some reason, that means the user provided incorrect
        // payload data either during transaction creation or execution.
        let deserialization_error = PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT)
            .finish(Location::Undefined);
        let payload_bytes =
            bcs::from_bytes::<Vec<u8>>(payload_bytes).map_err(|_| deserialization_error.clone())?;
        let payload = bcs::from_bytes::<MultisigTransactionPayload>(&payload_bytes)
            .map_err(|_| deserialization_error)?;

        // Step 2: Execute the target payload. Transaction failure here is tolerated. In case of any
        // failures, we'll discard the session and start a new one. This ensures that any data
        // changes are not persisted.
        // The multisig transaction would still be considered executed even if execution fails.
        let execution_result = match payload {
            MultisigTransactionPayload::EntryFunction(entry_function) => self
                .execute_multisig_entry_function(
                    &mut session,
                    gas_meter,
                    txn_payload.multisig_address,
                    &entry_function,
                    new_published_modules_loaded,
                ),
        };

        // Step 3: Call post transaction cleanup function in multisig account module with the result
        // from Step 2.
        // Note that we don't charge execution or writeset gas for cleanup routines. This is
        // consistent with the high-level success/failure cleanup routines for user transactions.
        let cleanup_args = serialize_values(&vec![
            MoveValue::Address(txn_data.sender),
            MoveValue::Address(txn_payload.multisig_address),
            MoveValue::vector_u8(payload_bytes),
        ]);
        let respawned_session = if let Err(execution_error) = execution_result {
            // Invalidate the loader cache in case there was a new module loaded from a module
            // publish request that failed.
            // This is redundant with the logic in execute_user_transaction but unfortunately is
            // necessary here as executing the underlying call can fail without this function
            // returning an error to execute_user_transaction.
            if *new_published_modules_loaded {
                self.vm_impl.mark_loader_cache_as_invalid();
            };
            self.failure_multisig_payload_cleanup(
                resolver,
                execution_error,
                txn_data,
                cleanup_args,
            )?
        } else {
            self.success_multisig_payload_cleanup(
                resolver,
                session,
                gas_meter,
                txn_data,
                cleanup_args,
                change_set_configs,
            )?
        };

        // TODO(Gas): Charge for aggregator writes
        self.success_transaction_cleanup(
            respawned_session,
            gas_meter,
            txn_data,
            log_context,
            change_set_configs,
        )
    }

    fn execute_multisig_entry_function(
        &self,
        session: &mut SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        multisig_address: AccountAddress,
        payload: &EntryFunction,
        new_published_modules_loaded: &mut bool,
    ) -> Result<(), VMStatus> {
        // If txn args are not valid, we'd still consider the transaction as executed but
        // failed. This is primarily because it's unrecoverable at this point.
        self.validate_and_execute_entry_function(
            session,
            gas_meter,
            vec![multisig_address],
            payload,
        )?;

        // Resolve any pending module publishes in case the multisig transaction is deploying
        // modules.
        self.resolve_pending_code_publish(session, gas_meter, new_published_modules_loaded)?;
        Ok(())
    }

    fn success_multisig_payload_cleanup<'r, 'l>(
        &'l self,
        resolver: &'r impl AptosMoveResolver,
        session: SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        cleanup_args: Vec<Vec<u8>>,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<RespawnedSession<'r, 'l>, VMStatus> {
        // Charge gas for write set before we do cleanup. This ensures we don't charge gas for
        // cleanup write set changes, which is consistent with outer-level success cleanup
        // flow. We also wouldn't need to worry that we run out of gas when doing cleanup.
        let mut respawned_session = self.charge_change_set_and_respawn_session(
            session,
            resolver,
            gas_meter,
            change_set_configs,
            txn_data,
        )?;
        respawned_session.execute(|session| {
            session
                .execute_function_bypass_visibility(
                    &MULTISIG_ACCOUNT_MODULE,
                    SUCCESSFUL_TRANSACTION_EXECUTION_CLEANUP,
                    vec![],
                    cleanup_args,
                    &mut UnmeteredGasMeter,
                )
                .map_err(|e| e.into_vm_status())
        })?;
        Ok(respawned_session)
    }

    fn failure_multisig_payload_cleanup<'r, 'l>(
        &'l self,
        resolver: &'r impl AptosMoveResolver,
        execution_error: VMStatus,
        txn_data: &TransactionMetadata,
        mut cleanup_args: Vec<Vec<u8>>,
    ) -> Result<RespawnedSession<'r, 'l>, VMStatus> {
        // Start a fresh session for running cleanup that does not contain any changes from
        // the inner function call earlier (since it failed).
        let mut respawned_session = RespawnedSession::spawn(
            self,
            SessionId::epilogue_meta(txn_data),
            resolver,
            VMChangeSet::empty(),
            0.into(),
        )?;

        let execution_error = ExecutionError::try_from(execution_error)
            .map_err(|_| VMStatus::error(StatusCode::UNREACHABLE, None))?;
        // Serialization is not expected to fail so we're using invariant_violation error here.
        cleanup_args.push(bcs::to_bytes(&execution_error).map_err(|_| {
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("MultiSig payload cleanup error.".to_string())
                .finish(Location::Undefined)
        })?);
        respawned_session.execute(|session| {
            session
                .execute_function_bypass_visibility(
                    &MULTISIG_ACCOUNT_MODULE,
                    FAILED_TRANSACTION_EXECUTION_CLEANUP,
                    vec![],
                    cleanup_args,
                    &mut UnmeteredGasMeter,
                )
                .map_err(|e| e.into_vm_status())
        })?;
        Ok(respawned_session)
    }

    fn verify_module_bundle(
        session: &mut SessionExt,
        module_bundle: &ModuleBundle,
    ) -> VMResult<()> {
        for module_blob in module_bundle.iter() {
            match CompiledModule::deserialize_with_config(
                module_blob.code(),
                &session.get_vm_config().deserializer_config,
            ) {
                Ok(module) => {
                    // verify the module doesn't exist
                    if session.load_module(&module.self_id()).is_ok() {
                        return Err(verification_error(
                            StatusCode::DUPLICATE_MODULE_NAME,
                            IndexKind::AddressIdentifier,
                            module.self_handle_idx().0,
                        )
                        .finish(Location::Undefined));
                    }
                },
                Err(err) => return Err(err.finish(Location::Undefined)),
            }
        }
        Ok(())
    }

    /// Execute all module initializers.
    fn execute_module_initialization(
        &self,
        session: &mut SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        modules: &[CompiledModule],
        exists: BTreeSet<ModuleId>,
        senders: &[AccountAddress],
        new_published_modules_loaded: &mut bool,
    ) -> VMResult<()> {
        let init_func_name = ident_str!("init_module");
        for module in modules {
            if exists.contains(&module.self_id()) {
                // Call initializer only on first publish.
                continue;
            }
            *new_published_modules_loaded = true;
            let init_function = session.load_function(&module.self_id(), init_func_name, &[]);
            // it is ok to not have init_module function
            // init_module function should be (1) private and (2) has no return value
            // Note that for historic reasons, verification here is treated
            // as StatusCode::CONSTRAINT_NOT_SATISFIED, there this cannot be unified
            // with the general verify_module above.
            if init_function.is_ok() {
                if verifier::module_init::verify_module_init_function(module).is_ok() {
                    let args: Vec<Vec<u8>> = senders
                        .iter()
                        .map(|s| MoveValue::Signer(*s).simple_serialize().unwrap())
                        .collect();
                    session.execute_function_bypass_visibility(
                        &module.self_id(),
                        init_func_name,
                        vec![],
                        args,
                        gas_meter,
                    )?;
                } else {
                    return Err(PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
                        .finish(Location::Undefined));
                }
            }
        }
        Ok(())
    }

    /// Deserialize a module bundle.
    fn deserialize_module_bundle(&self, modules: &ModuleBundle) -> VMResult<Vec<CompiledModule>> {
        let max_version = get_max_binary_format_version(self.vm_impl.get_features(), None);
        let max_identifier_size = if self
            .vm_impl
            .get_features()
            .is_enabled(FeatureFlag::LIMIT_MAX_IDENTIFIER_LENGTH)
        {
            IDENTIFIER_SIZE_MAX
        } else {
            LEGACY_IDENTIFIER_SIZE_MAX
        };
        let config = DeserializerConfig::new(max_version, max_identifier_size);
        let mut result = vec![];
        for module_blob in modules.iter() {
            match CompiledModule::deserialize_with_config(module_blob.code(), &config) {
                Ok(module) => {
                    result.push(module);
                },
                Err(_err) => {
                    return Err(PartialVMError::new(StatusCode::CODE_DESERIALIZATION_ERROR)
                        .finish(Location::Undefined))
                },
            }
        }
        Ok(result)
    }

    /// Execute a module bundle load request.
    /// TODO: this is going to be deprecated and removed in favor of code publishing via
    /// NativeCodeContext
    fn execute_modules(
        &self,
        resolver: &impl AptosMoveResolver,
        mut session: SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        modules: &ModuleBundle,
        log_context: &AdapterLogSchema,
        new_published_modules_loaded: &mut bool,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        if MODULE_BUNDLE_DISALLOWED.load(Ordering::Relaxed) {
            return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
        }
        fail_point!("move_adapter::execute_module", |_| {
            Err(VMStatus::error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                None,
            ))
        });

        gas_meter.charge_intrinsic_gas_for_transaction(txn_data.transaction_size())?;

        Self::verify_module_bundle(&mut session, modules)?;
        session.publish_module_bundle_with_compat_config(
            modules.clone().into_inner(),
            txn_data.sender(),
            gas_meter,
            Compatibility::new(
                true,
                true,
                !self
                    .vm_impl
                    .get_features()
                    .is_enabled(FeatureFlag::TREAT_FRIEND_AS_PRIVATE),
            ),
        )?;

        // call init function of the each module
        self.execute_module_initialization(
            &mut session,
            gas_meter,
            &self.deserialize_module_bundle(modules)?,
            BTreeSet::new(),
            &[txn_data.sender()],
            new_published_modules_loaded,
        )?;

        let respawned_session = self.charge_change_set_and_respawn_session(
            session,
            resolver,
            gas_meter,
            change_set_configs,
            txn_data,
        )?;

        self.success_transaction_cleanup(
            respawned_session,
            gas_meter,
            txn_data,
            log_context,
            change_set_configs,
        )
    }

    /// Resolve a pending code publish request registered via the NativeCodeContext.
    fn resolve_pending_code_publish(
        &self,
        session: &mut SessionExt,
        gas_meter: &mut impl AptosGasMeter,
        new_published_modules_loaded: &mut bool,
    ) -> VMResult<()> {
        if let Some(PublishRequest {
            destination,
            bundle,
            expected_modules,
            allowed_deps,
            check_compat: _,
        }) = session.extract_publish_request()
        {
            // TODO: unfortunately we need to deserialize the entire bundle here to handle
            // `init_module` and verify some deployment conditions, while the VM need to do
            // the deserialization again. Consider adding an API to MoveVM which allows to
            // directly pass CompiledModule.
            let modules = self.deserialize_module_bundle(&bundle)?;

            // Validate the module bundle
            self.validate_publish_request(session, &modules, expected_modules, allowed_deps)?;

            // Check what modules exist before publishing.
            let mut exists = BTreeSet::new();
            for m in &modules {
                let id = m.self_id();
                if session.exists_module(&id)? {
                    exists.insert(id);
                }
            }

            // Publish the bundle and execute initializers
            // publish_module_bundle doesn't actually load the published module into
            // the loader cache. It only puts the module data in the data cache.
            return_on_failure!(session.publish_module_bundle_with_compat_config(
                bundle.into_inner(),
                destination,
                gas_meter,
                Compatibility::new(
                    true,
                    true,
                    !self
                        .vm_impl
                        .get_features()
                        .is_enabled(FeatureFlag::TREAT_FRIEND_AS_PRIVATE),
                ),
            ));

            self.execute_module_initialization(
                session,
                gas_meter,
                &modules,
                exists,
                &[destination],
                new_published_modules_loaded,
            )
        } else {
            Ok(())
        }
    }

    /// Validate a publish request.
    fn validate_publish_request(
        &self,
        session: &mut SessionExt,
        modules: &[CompiledModule],
        mut expected_modules: BTreeSet<String>,
        allowed_deps: Option<BTreeMap<AccountAddress, BTreeSet<String>>>,
    ) -> VMResult<()> {
        for m in modules {
            if !expected_modules.remove(m.self_id().name().as_str()) {
                return Err(Self::metadata_validation_error(&format!(
                    "unregistered module: '{}'",
                    m.self_id().name()
                )));
            }
            if let Some(allowed) = &allowed_deps {
                for dep in m.immediate_dependencies() {
                    if !allowed
                        .get(dep.address())
                        .map(|modules| {
                            modules.contains("") || modules.contains(dep.name().as_str())
                        })
                        .unwrap_or(false)
                    {
                        return Err(Self::metadata_validation_error(&format!(
                            "unregistered dependency: '{}'",
                            dep
                        )));
                    }
                }
            }
            aptos_framework::verify_module_metadata(
                m,
                self.vm_impl.get_features(),
                self.vm_impl.get_timed_features(),
            )
            .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
        }
        verifier::resource_groups::validate_resource_groups(
            session,
            modules,
            self.vm_impl
                .get_features()
                .is_enabled(FeatureFlag::SAFER_RESOURCE_GROUPS),
        )?;
        verifier::event_validation::validate_module_events(session, modules)?;

        if !expected_modules.is_empty() {
            return Err(Self::metadata_validation_error(
                "not all registered modules published",
            ));
        }
        Ok(())
    }

    fn metadata_validation_error(msg: &str) -> VMError {
        PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
            .with_message(format!("metadata and code bundle mismatch: {}", msg))
            .finish(Location::Undefined)
    }

    fn make_standard_gas_meter(
        &self,
        balance: Gas,
        log_context: &AdapterLogSchema,
    ) -> Result<MemoryTrackedGasMeter<StandardGasMeter<StandardGasAlgebra>>, VMStatus> {
        Ok(MemoryTrackedGasMeter::new(StandardGasMeter::new(
            StandardGasAlgebra::new(
                self.vm_impl.get_gas_feature_version(),
                self.vm_impl.get_gas_parameters(log_context)?.vm.clone(),
                self.vm_impl
                    .get_storage_gas_parameters(log_context)?
                    .clone(),
                balance,
            ),
        )))
    }

    fn validate_signed_transaction(
        &self,
        session: &mut SessionExt,
        resolver: &impl AptosMoveResolver,
        transaction: &SignedTransaction,
        transaction_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
    ) -> Result<(), VMStatus> {
        // Check transaction format.
        if transaction.contains_duplicate_signers() {
            return Err(VMStatus::error(
                StatusCode::SIGNERS_CONTAIN_DUPLICATES,
                None,
            ));
        }

        self.run_prologue_with_payload(
            session,
            resolver,
            transaction.payload(),
            transaction_data,
            log_context,
        )
    }

    // Called when the execution of the user transaction fails, in order to discard the
    // transaction, or clean up the failed state.
    fn on_user_transaction_execution_failure(
        &self,
        err: VMStatus,
        resolver: &impl AptosMoveResolver,
        txn_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
        gas_meter: &mut impl AptosGasMeter,
        storage_gas_params: &StorageGasParameters,
        new_published_modules_loaded: bool,
    ) -> (VMStatus, VMOutput) {
        // Invalidate the loader cache in case there was a new module loaded from a module
        // publish request that failed.
        // This ensures the loader cache is flushed later to align storage with the cache.
        // None of the modules in the bundle will be committed to storage,
        // but some of them may have ended up in the cache.
        if new_published_modules_loaded {
            self.vm_impl.mark_loader_cache_as_invalid();
        };

        let txn_status = TransactionStatus::from_vm_status(
            err.clone(),
            self.vm_impl
                .get_features()
                .is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION),
        );
        if txn_status.is_discarded() {
            discard_error_vm_status(err)
        } else {
            self.failed_transaction_cleanup_and_keep_vm_status(
                err,
                gas_meter,
                txn_data,
                resolver,
                log_context,
                &storage_gas_params.change_set_configs,
            )
        }
    }

    fn process_validator_transaction(
        &self,
        _resolver: &impl AptosMoveResolver,
        _txn: ValidatorTransaction,
        _log_context: &AdapterLogSchema,
    ) -> (VMStatus, VMOutput) {
        (
            VMStatus::Executed,
            VMOutput::empty_with_status(TransactionStatus::Keep(ExecutionStatus::Success)),
        )
    }

    fn execute_user_transaction_impl(
        &self,
        resolver: &impl AptosMoveResolver,
        txn: &SignedTransaction,
        log_context: &AdapterLogSchema,
        gas_meter: &mut impl AptosGasMeter,
    ) -> (VMStatus, VMOutput) {
        // Revalidate the transaction.
        let txn_data = TransactionMetadata::new(txn);
        let mut session = self
            .vm_impl
            .new_session(resolver, SessionId::prologue_meta(&txn_data));
        if let Err(err) =
            self.validate_signed_transaction(&mut session, resolver, txn, &txn_data, log_context)
        {
            return discard_error_vm_status(err);
        };

        if self.vm_impl.get_gas_feature_version() >= 1 {
            // Create a new session so that the data cache is flushed.
            // This is to ensure we correctly charge for loading certain resources, even if they
            // have been previously cached in the prologue.
            //
            // TODO(Gas): Do this in a better way in the future, perhaps without forcing the data cache to be flushed.
            // By releasing resource group cache, we start with a fresh slate for resource group
            // cost accounting.
            resolver.release_resource_group_cache();
            session = self
                .vm_impl
                .new_session(resolver, SessionId::txn_meta(&txn_data));
        }

        if let aptos_types::transaction::authenticator::TransactionAuthenticator::FeePayer {
            ..
        } = &txn.authenticator_ref()
        {
            if self
                .vm_impl
                .get_features()
                .is_enabled(FeatureFlag::SPONSORED_AUTOMATIC_ACCOUNT_CREATION)
            {
                if let Err(err) = session.execute_function_bypass_visibility(
                    &ACCOUNT_MODULE,
                    CREATE_ACCOUNT_IF_DOES_NOT_EXIST,
                    vec![],
                    serialize_values(&vec![MoveValue::Address(txn.sender())]),
                    gas_meter,
                ) {
                    return discard_error_vm_status(err.into());
                };
            }
        }

        let storage_gas_params =
            unwrap_or_discard!(self.vm_impl.get_storage_gas_parameters(log_context));

        // We keep track of whether any newly published modules are loaded into the Vm's loader
        // cache as part of executing transactions. This would allow us to decide whether the cache
        // should be flushed later.
        let mut new_published_modules_loaded = false;
        let result = match txn.payload() {
            payload @ TransactionPayload::Script(_)
            | payload @ TransactionPayload::EntryFunction(_) => self
                .execute_script_or_entry_function(
                    resolver,
                    session,
                    gas_meter,
                    &txn_data,
                    payload,
                    log_context,
                    &mut new_published_modules_loaded,
                    &storage_gas_params.change_set_configs,
                ),
            TransactionPayload::Multisig(payload) => {
                if self.is_simulation {
                    self.simulate_multisig_transaction(
                        payload,
                        session,
                        resolver,
                        &txn_data,
                        log_context,
                        gas_meter,
                        &mut new_published_modules_loaded,
                        &storage_gas_params.change_set_configs,
                    )
                } else {
                    self.execute_multisig_transaction(
                        resolver,
                        session,
                        gas_meter,
                        &txn_data,
                        payload,
                        log_context,
                        &mut new_published_modules_loaded,
                        &storage_gas_params.change_set_configs,
                    )
                }
            },

            // Deprecated. Will be removed in the future.
            TransactionPayload::ModuleBundle(m) => self.execute_modules(
                resolver,
                session,
                gas_meter,
                &txn_data,
                m,
                log_context,
                &mut new_published_modules_loaded,
                &storage_gas_params.change_set_configs,
            ),
        };

        let gas_usage = txn_data
            .max_gas_amount()
            .checked_sub(gas_meter.balance())
            .expect("Balance should always be less than or equal to max gas amount set");
        TXN_GAS_USAGE.observe(u64::from(gas_usage) as f64);

        result.unwrap_or_else(|err| {
            self.on_user_transaction_execution_failure(
                err,
                resolver,
                &txn_data,
                log_context,
                gas_meter,
                storage_gas_params,
                new_published_modules_loaded,
            )
        })
    }

    fn execute_user_transaction(
        &self,
        resolver: &impl AptosMoveResolver,
        txn: &SignedTransaction,
        log_context: &AdapterLogSchema,
    ) -> (VMStatus, VMOutput) {
        let balance = TransactionMetadata::new(txn).max_gas_amount();
        // TODO: would we end up having a diverging behavior by creating the gas meter at an earlier time?
        let mut gas_meter = unwrap_or_discard!(self.make_standard_gas_meter(balance, log_context));

        self.execute_user_transaction_impl(resolver, txn, log_context, &mut gas_meter)
    }

    pub fn execute_user_transaction_with_custom_gas_meter<G, F>(
        &self,
        resolver: &impl AptosMoveResolver,
        txn: &SignatureCheckedTransaction,
        log_context: &AdapterLogSchema,
        make_gas_meter: F,
    ) -> Result<(VMStatus, VMOutput, G), VMStatus>
    where
        G: AptosGasMeter,
        F: FnOnce(u64, VMGasParameters, StorageGasParameters, Gas) -> Result<G, VMStatus>,
    {
        // TODO(Gas): avoid creating txn metadata twice.
        let balance = TransactionMetadata::new(txn).max_gas_amount();
        let mut gas_meter = make_gas_meter(
            self.vm_impl.get_gas_feature_version(),
            self.vm_impl.get_gas_parameters(log_context)?.vm.clone(),
            self.vm_impl
                .get_storage_gas_parameters(log_context)?
                .clone(),
            balance,
        )?;
        let (status, output) =
            self.execute_user_transaction_impl(resolver, txn, log_context, &mut gas_meter);

        Ok((status, output, gas_meter))
    }

    fn execute_write_set(
        &self,
        resolver: &impl AptosMoveResolver,
        write_set_payload: &WriteSetPayload,
        txn_sender: Option<AccountAddress>,
        session_id: SessionId,
    ) -> Result<VMChangeSet, VMStatus> {
        let mut gas_meter = UnmeteredGasMeter;
        let change_set_configs = ChangeSetConfigs::unlimited_at_gas_feature_version(
            self.vm_impl.get_gas_feature_version(),
        );

        match write_set_payload {
            WriteSetPayload::Direct(change_set) => VMChangeSet::try_from_storage_change_set(
                change_set.clone(),
                &change_set_configs,
                resolver.is_delayed_field_optimization_capable(),
            ),
            WriteSetPayload::Script { script, execute_as } => {
                let mut tmp_session = self.vm_impl.new_session(resolver, session_id);
                let senders = match txn_sender {
                    None => vec![*execute_as],
                    Some(sender) => vec![sender, *execute_as],
                };

                let loaded_func =
                    tmp_session.load_script(script.code(), script.ty_args().to_vec())?;
                let args =
                    verifier::transaction_arg_validation::validate_combine_signer_and_txn_args(
                        &mut tmp_session,
                        senders,
                        convert_txn_args(script.args()),
                        &loaded_func,
                        self.vm_impl
                            .get_features()
                            .is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS),
                    )?;

                return_on_failure!(tmp_session.execute_script(
                    script.code(),
                    script.ty_args().to_vec(),
                    args,
                    &mut gas_meter,
                ));
                Ok(tmp_session.finish(&change_set_configs)?)
            },
        }
    }

    fn read_change_set(
        &self,
        executor_view: &dyn ExecutorView,
        resource_group_view: &dyn ResourceGroupView,
        change_set: &VMChangeSet,
    ) -> Result<(), VMStatus> {
        assert!(
            change_set.aggregator_v1_write_set().is_empty(),
            "Waypoint change set should not have any aggregator writes."
        );

        // All Move executions satisfy the read-before-write property. Thus we need to read each
        // access path that the write set is going to update.
        for state_key in change_set.module_write_set().keys() {
            executor_view
                .get_module_state_value(state_key)
                .map_err(|_| VMStatus::error(StatusCode::STORAGE_ERROR, None))?;
        }
        for state_key in change_set.resource_write_set().keys() {
            executor_view
                .get_resource_state_value(state_key, None)
                .map_err(|_| VMStatus::error(StatusCode::STORAGE_ERROR, None))?;
        }
        for (state_key, group_write) in change_set.resource_group_write_set().iter() {
            for (tag, (_, maybe_layout)) in group_write.inner_ops() {
                resource_group_view
                    .get_resource_from_group(state_key, tag, maybe_layout.as_deref())
                    .map_err(|_| VMStatus::error(StatusCode::STORAGE_ERROR, None))?;
            }
        }

        Ok(())
    }

    fn validate_waypoint_change_set(
        change_set: &VMChangeSet,
        log_context: &AdapterLogSchema,
    ) -> Result<(), VMStatus> {
        let has_new_block_event = change_set
            .events()
            .iter()
            .any(|(e, _)| e.event_key() == Some(&new_block_event_key()));
        let has_new_epoch_event = change_set
            .events()
            .iter()
            .any(|(e, _)| e.event_key() == Some(&new_epoch_event_key()));
        if has_new_block_event && has_new_epoch_event {
            Ok(())
        } else {
            error!(
                *log_context,
                "[aptos_vm] waypoint txn needs to emit new epoch and block"
            );
            Err(VMStatus::error(StatusCode::INVALID_WRITE_SET, None))
        }
    }

    pub(crate) fn process_waypoint_change_set(
        &self,
        resolver: &impl AptosMoveResolver,
        write_set_payload: WriteSetPayload,
        log_context: &AdapterLogSchema,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        // TODO: user specified genesis id to distinguish different genesis write sets
        let genesis_id = HashValue::zero();
        let change_set = self.execute_write_set(
            resolver,
            &write_set_payload,
            Some(aptos_types::account_config::reserved_vm_address()),
            SessionId::genesis(genesis_id),
        )?;

        Self::validate_waypoint_change_set(&change_set, log_context)?;
        self.read_change_set(
            resolver.as_executor_view(),
            resolver.as_resource_group_view(),
            &change_set,
        )?;

        SYSTEM_TRANSACTIONS_EXECUTED.inc();

        let output = VMOutput::new(change_set, FeeStatement::zero(), VMStatus::Executed.into());
        Ok((VMStatus::Executed, output))
    }

    pub(crate) fn process_block_prologue(
        &self,
        resolver: &impl AptosMoveResolver,
        block_metadata: BlockMetadata,
        log_context: &AdapterLogSchema,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        fail_point!("move_adapter::process_block_prologue", |_| {
            Err(VMStatus::error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                None,
            ))
        });

        let mut gas_meter = UnmeteredGasMeter;
        let mut session = self
            .vm_impl
            .new_session(resolver, SessionId::block_meta(&block_metadata));

        let args = serialize_values(
            &block_metadata.get_prologue_move_args(account_config::reserved_vm_address()),
        );
        session
            .execute_function_bypass_visibility(
                &BLOCK_MODULE,
                BLOCK_PROLOGUE,
                vec![],
                args,
                &mut gas_meter,
            )
            .map(|_return_vals| ())
            .or_else(|e| {
                expect_only_successful_execution(e, BLOCK_PROLOGUE.as_str(), log_context)
            })?;
        SYSTEM_TRANSACTIONS_EXECUTED.inc();

        let output = get_transaction_output(
            session,
            FeeStatement::zero(),
            ExecutionStatus::Success,
            &self
                .vm_impl
                .get_storage_gas_parameters(log_context)?
                .change_set_configs,
        )?;
        Ok((VMStatus::Executed, output))
    }

    pub fn execute_view_function(
        state_view: &impl StateView,
        module_id: ModuleId,
        func_name: Identifier,
        type_args: Vec<TypeTag>,
        arguments: Vec<Vec<u8>>,
        gas_budget: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let resolver = state_view.as_move_resolver();
        let vm = AptosVM::new(&resolver);
        let log_context = AdapterLogSchema::new(state_view.id(), 0);
        let mut gas_meter =
            MemoryTrackedGasMeter::new(StandardGasMeter::new(StandardGasAlgebra::new(
                vm.vm_impl.get_gas_feature_version(),
                vm.vm_impl.get_gas_parameters(&log_context)?.vm.clone(),
                vm.vm_impl.get_storage_gas_parameters(&log_context)?.clone(),
                gas_budget,
            )));

        let mut session = vm.vm_impl.new_session(&resolver, SessionId::Void);

        let func_inst = session.load_function(&module_id, &func_name, &type_args)?;
        let metadata = vm.vm_impl.extract_module_metadata(&module_id);
        let arguments = verifier::view_function::validate_view_function(
            &mut session,
            arguments,
            func_name.as_ident_str(),
            &func_inst,
            metadata.as_ref().map(Arc::as_ref),
            vm.vm_impl
                .get_features()
                .is_enabled(FeatureFlag::STRUCT_CONSTRUCTORS),
        )?;

        Ok(session
            .execute_function_bypass_visibility(
                &module_id,
                func_name.as_ident_str(),
                type_args,
                arguments,
                &mut gas_meter,
            )
            .map_err(|err| anyhow!("Failed to execute function: {:?}", err))?
            .return_values
            .into_iter()
            .map(|(bytes, _ty)| bytes)
            .collect::<Vec<_>>())
    }

    fn run_prologue_with_payload(
        &self,
        session: &mut SessionExt,
        resolver: &impl AptosMoveResolver,
        payload: &TransactionPayload,
        txn_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
    ) -> Result<(), VMStatus> {
        match payload {
            TransactionPayload::Script(_) => {
                self.vm_impl.check_gas(resolver, txn_data, log_context)?;
                self.vm_impl
                    .run_script_prologue(session, txn_data, log_context)
            },
            TransactionPayload::EntryFunction(_) => {
                // NOTE: Script and EntryFunction shares the same prologue
                self.vm_impl.check_gas(resolver, txn_data, log_context)?;
                self.vm_impl
                    .run_script_prologue(session, txn_data, log_context)
            },
            TransactionPayload::Multisig(multisig_payload) => {
                self.vm_impl.check_gas(resolver, txn_data, log_context)?;
                // Still run script prologue for multisig transaction to ensure the same tx
                // validations are still run for this multisig execution tx, which is submitted by
                // one of the owners.
                self.vm_impl
                    .run_script_prologue(session, txn_data, log_context)?;
                // Skip validation if this is part of tx simulation.
                // This allows simulating multisig txs without having to first create the multisig
                // tx.
                if !self.is_simulation {
                    self.vm_impl.run_multisig_prologue(
                        session,
                        txn_data,
                        multisig_payload,
                        log_context,
                    )
                } else {
                    Ok(())
                }
            },

            // Deprecated. Will be removed in the future.
            TransactionPayload::ModuleBundle(_module) => {
                if MODULE_BUNDLE_DISALLOWED.load(Ordering::Relaxed) {
                    return Err(VMStatus::error(StatusCode::FEATURE_UNDER_GATING, None));
                }
                self.vm_impl.check_gas(resolver, txn_data, log_context)?;
                self.vm_impl
                    .run_module_prologue(session, txn_data, log_context)
            },
        }
    }

    pub fn should_restart_execution(vm_output: &VMOutput) -> bool {
        let new_epoch_event_key = aptos_types::on_chain_config::new_epoch_event_key();
        vm_output
            .change_set()
            .events()
            .iter()
            .any(|(event, _)| event.event_key() == Some(&new_epoch_event_key))
    }

    /// Executes a single transaction (including user transactions, block
    /// metadata and state checkpoint, etc.).
    /// *Precondition:* VM has to be instantiated in execution mode.
    pub fn execute_single_transaction(
        &self,
        txn: &SignatureVerifiedTransaction,
        resolver: &impl AptosMoveResolver,
        log_context: &AdapterLogSchema,
    ) -> Result<(VMStatus, VMOutput, Option<String>), VMStatus> {
        assert!(!self.is_simulation, "VM has to be created for execution");

        if let SignatureVerifiedTransaction::Invalid(_) = txn {
            let (vm_status, output) =
                discard_error_vm_status(VMStatus::error(StatusCode::INVALID_SIGNATURE, None));
            return Ok((vm_status, output, None));
        }

        Ok(match txn.expect_valid() {
            BlockMetadataTransaction(block_metadata) => {
                fail_point!("aptos_vm::execution::block_metadata");
                let (vm_status, output) =
                    self.process_block_prologue(resolver, block_metadata.clone(), log_context)?;
                (vm_status, output, Some("block_prologue".to_string()))
            },
            GenesisTransaction(write_set_payload) => {
                let (vm_status, output) = self.process_waypoint_change_set(
                    resolver,
                    write_set_payload.clone(),
                    log_context,
                )?;
                (vm_status, output, Some("waypoint_write_set".to_string()))
            },
            UserTransaction(txn) => {
                fail_point!("aptos_vm::execution::user_transaction");
                let sender = txn.sender().to_hex();
                let _timer = TXN_TOTAL_SECONDS.start_timer();
                let (vm_status, output) = self.execute_user_transaction(resolver, txn, log_context);

                if let StatusType::InvariantViolation = vm_status.status_type() {
                    match vm_status.status_code() {
                        // Type resolution failure can be triggered by user input when providing a bad type argument, skip this case.
                        StatusCode::TYPE_RESOLUTION_FAILURE
                        if vm_status.sub_status()
                            == Some(move_core_types::vm_status::sub_status::type_resolution_failure::EUSER_TYPE_LOADING_FAILURE) => {},
                        // The known Move function failure and type resolution failure could be a result of speculative execution. Use speculative logger.
                        StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION
                        | StatusCode::TYPE_RESOLUTION_FAILURE => {
                            speculative_error!(
                                log_context,
                                format!(
                                    "[aptos_vm] Transaction breaking invariant violation. txn: {:?}, status: {:?}",
                                    bcs::to_bytes::<SignedTransaction>(txn),
                                    vm_status
                                ),
                            );
                        },
                        // Paranoid mode failure. We need to be alerted about this ASAP.
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if vm_status.sub_status()
                            == Some(move_core_types::vm_status::sub_status::unknown_invariant_violation::EPARANOID_FAILURE) =>
                            {
                                error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking paranoid mode. txn: {:?}, status: {:?}",
                                bcs::to_bytes::<SignedTransaction>(txn),
                                vm_status,
                            );
                            },
                        // Paranoid mode failure but with reference counting
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if vm_status.sub_status()
                            == Some(move_core_types::vm_status::sub_status::unknown_invariant_violation::EREFERENCE_COUNTING_FAILURE) =>
                            {
                                error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking paranoid mode. txn: {:?}, status: {:?}",
                                bcs::to_bytes::<SignedTransaction>(txn),
                                vm_status,
                            );
                            },
                        // Ignore DelayedFields speculative errors as it can be intentionally triggered by parallel execution.
                        StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR => (),
                        // Ignore Storage Error as currently it sometimes wraps speculative errors
                        // TODO[agg_v2](fix) propagate SPECULATIVE_EXECUTION_ABORT_ERROR correctly, and remove storage from valid errors here.
                        StatusCode::STORAGE_ERROR => (),
                        // We will log the rest of invariant violation directly with regular logger as they shouldn't happen.
                        //
                        // TODO: Add different counters for the error categories here.
                        _ => {
                            error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking invariant violation. txn: {:?}, status: {:?}",
                                bcs::to_bytes::<SignedTransaction>(txn),
                                vm_status,
                            );
                        },
                    }
                }

                // Increment the counter for user transactions executed.
                let counter_label = match output.status() {
                    TransactionStatus::Keep(_) => Some("success"),
                    TransactionStatus::Discard(_) => Some("discarded"),
                    TransactionStatus::Retry => None,
                };
                if let Some(label) = counter_label {
                    USER_TRANSACTIONS_EXECUTED.with_label_values(&[label]).inc();
                }
                (vm_status, output, Some(sender))
            },
            StateCheckpoint(_) => {
                let status = TransactionStatus::Keep(ExecutionStatus::Success);
                let output = VMOutput::empty_with_status(status);
                (VMStatus::Executed, output, Some("state_checkpoint".into()))
            },
            Transaction::ValidatorTransaction(txn) => {
                fail_point!("aptos_vm::execution::validator_transaction");
                let (vm_status, output) =
                    self.process_validator_transaction(resolver, txn.clone(), log_context);
                (vm_status, output, Some("validator_transaction".to_string()))
            },
        })
    }
}

// Executor external API
impl VMExecutor for AptosVM {
    /// Execute a block of `transactions`. The output vector will have the exact same length as the
    /// input vector. The discarded transactions will be marked as `TransactionStatus::Discard` and
    /// have an empty `WriteSet`. Also `state_view` is immutable, and does not have interior
    /// mutability. Writes to be applied to the data view are encoded in the write set part of a
    /// transaction output.
    fn execute_block(
        transactions: &[SignatureVerifiedTransaction],
        state_view: &(impl StateView + Sync),
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        fail_point!("move_adapter::execute_block", |_| {
            Err(VMStatus::error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                None,
            ))
        });
        let log_context = AdapterLogSchema::new(state_view.id(), 0);
        info!(
            log_context,
            "Executing block, transaction count: {}",
            transactions.len()
        );

        let count = transactions.len();
        let ret = BlockAptosVM::execute_block::<
            _,
            NoOpTransactionCommitHook<AptosTransactionOutput, VMStatus>,
        >(
            Arc::clone(&RAYON_EXEC_POOL),
            transactions,
            state_view,
            BlockExecutorConfig {
                local: BlockExecutorLocalConfig {
                    concurrency_level: Self::get_concurrency_level(),
                },
                onchain: onchain_config,
            },
            None,
        );
        if ret.is_ok() {
            // Record the histogram count for transactions per block.
            BLOCK_TRANSACTION_COUNT.observe(count as f64);
        }
        ret
    }

    fn execute_block_sharded<S: StateView + Sync + Send + 'static, C: ExecutorClient<S>>(
        sharded_block_executor: &ShardedBlockExecutor<S, C>,
        transactions: PartitionedTransactions,
        state_view: Arc<S>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>, VMStatus> {
        let log_context = AdapterLogSchema::new(state_view.id(), 0);
        info!(
            log_context,
            "Executing block, transaction count: {}",
            transactions.num_txns()
        );

        let count = transactions.num_txns();
        let ret = sharded_block_executor.execute_block(
            state_view,
            transactions,
            AptosVM::get_concurrency_level(),
            onchain_config,
        );
        if ret.is_ok() {
            // Record the histogram count for transactions per block.
            BLOCK_TRANSACTION_COUNT.observe(count as f64);
        }
        ret
    }
}

// VMValidator external API
impl VMValidator for AptosVM {
    /// Determine if a transaction is valid. Will return `None` if the transaction is accepted,
    /// `Some(Err)` if the VM rejects it, with `Err` as an error code. Verification performs the
    /// following steps:
    /// 1. The signature on the `SignedTransaction` matches the public key included in the
    ///    transaction
    /// 2. The script to be executed is under given specific configuration.
    /// 3. Invokes `Account.prologue`, which checks properties such as the transaction has the
    /// right sequence number and the sender has enough balance to pay for the gas.
    /// TBD:
    /// 1. Transaction arguments matches the main function's type signature.
    ///    We don't check this item for now and would execute the check at execution time.
    fn validate_transaction(
        &self,
        transaction: SignedTransaction,
        state_view: &impl StateView,
    ) -> VMValidatorResult {
        let _timer = TXN_VALIDATION_SECONDS.start_timer();
        let log_context = AdapterLogSchema::new(state_view.id(), 0);

        if !self
            .vm_impl
            .get_features()
            .is_enabled(FeatureFlag::SINGLE_SENDER_AUTHENTICATOR)
        {
            if let aptos_types::transaction::authenticator::TransactionAuthenticator::SingleSender{ .. } = transaction.authenticator_ref() {
                return VMValidatorResult::error(StatusCode::FEATURE_UNDER_GATING);
            }
        }

        let txn = match transaction.check_signature() {
            Ok(t) => t,
            _ => {
                return VMValidatorResult::error(StatusCode::INVALID_SIGNATURE);
            },
        };
        let txn_data = TransactionMetadata::new(&txn);

        let resolver = self.as_move_resolver(&state_view);
        let mut session = self
            .vm_impl
            .new_session(&resolver, SessionId::prologue_meta(&txn_data));
        // Increment the counter for transactions verified.
        let (counter_label, result) = match self.validate_signed_transaction(
            &mut session,
            &resolver,
            &txn,
            &txn_data,
            &log_context,
        ) {
            Err(err) if err.status_code() != StatusCode::SEQUENCE_NUMBER_TOO_NEW => (
                "failure",
                VMValidatorResult::new(Some(err.status_code()), 0),
            ),
            _ => (
                "success",
                VMValidatorResult::new(None, txn.gas_unit_price()),
            ),
        };

        TRANSACTIONS_VALIDATED
            .with_label_values(&[counter_label])
            .inc();

        result
    }
}

// Ensure encapsulation of AptosVM APIs by using a wrapper.
pub struct AptosSimulationVM(AptosVM);

impl AptosSimulationVM {
    pub fn new(resolver: &impl AptosMoveResolver) -> Self {
        let mut vm = AptosVM::new(resolver);
        vm.is_simulation = true;
        Self(vm)
    }

    /// Simulates a signed transaction (i.e., executes it without performing
    /// signature verification) on a newly created VM instance.
    /// *Precondition:* the transaction must **not** have a valid signature.
    pub fn create_vm_and_simulate_signed_transaction(
        transaction: &SignedTransaction,
        state_view: &impl StateView,
    ) -> (VMStatus, TransactionOutput) {
        assert_err!(
            transaction.verify_signature(),
            "Simulated transaction should not have a valid signature"
        );

        let resolver = state_view.as_move_resolver();
        let vm = Self::new(&resolver);
        let log_context = AdapterLogSchema::new(state_view.id(), 0);

        let (vm_status, vm_output) =
            vm.0.execute_user_transaction(&resolver, transaction, &log_context);
        let txn_output = vm_output
            .try_into_transaction_output(&resolver)
            .expect("Materializing aggregator V1 deltas should never fail");
        (vm_status, txn_output)
    }
}
