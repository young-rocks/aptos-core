// Copyright © Aptos Foundation

use crate::{
    error::MempoolError, payload_manager::PayloadManager, state_computer::ExecutionProxy,
    state_replication::StateComputer, transaction_deduper::NoOpDeduper,
    transaction_filter::TransactionFilter, transaction_shuffler::NoOpShuffler,
    txn_notifier::TxnNotifier,
};
use aptos_config::config::transaction_filter_type::Filter;
use aptos_consensus_notifications::{ConsensusNotificationSender, Error};
use aptos_consensus_types::{block::Block, block_data::BlockData, executed_block::ExecutedBlock};
use aptos_crypto::HashValue;
use aptos_executor_types::{
    state_checkpoint_output::StateCheckpointOutput, BlockExecutorTrait, ExecutorResult,
    StateComputeResult,
};
use aptos_infallible::Mutex;
use aptos_types::{
    aggregate_signature::AggregateSignature,
    block_executor::{config::BlockExecutorConfigFromOnchain, partitioner::ExecutableBlock},
    contract_event::ContractEvent,
    epoch_state::EpochState,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    transaction::{ExecutionStatus, SignedTransaction, Transaction, TransactionStatus},
    validator_txn::ValidatorTransaction,
};
use futures_channel::oneshot;
use std::sync::Arc;
use tokio::runtime::Handle;

struct DummyStateSyncNotifier {
    invocations: Mutex<Vec<Vec<Transaction>>>,
}

impl DummyStateSyncNotifier {
    fn new() -> Self {
        Self {
            invocations: Mutex::new(vec![]),
        }
    }
}

#[async_trait::async_trait]
impl ConsensusNotificationSender for DummyStateSyncNotifier {
    async fn notify_new_commit(
        &self,
        transactions: Vec<Transaction>,
        _reconfiguration_events: Vec<ContractEvent>,
    ) -> Result<(), Error> {
        self.invocations.lock().push(transactions);
        Ok(())
    }

    async fn sync_to_target(&self, _target: LedgerInfoWithSignatures) -> Result<(), Error> {
        unreachable!()
    }
}

struct DummyTxnNotifier {}

#[async_trait::async_trait]
impl TxnNotifier for DummyTxnNotifier {
    async fn notify_failed_txn(
        &self,
        _txns: Vec<SignedTransaction>,
        _compute_results: &StateComputeResult,
        _block_gas_limit_enabled: bool,
    ) -> anyhow::Result<(), MempoolError> {
        Ok(())
    }
}

struct DummyBlockExecutor {
    blocks_received: Mutex<Vec<ExecutableBlock>>,
}

impl DummyBlockExecutor {
    fn new() -> Self {
        Self {
            blocks_received: Mutex::new(vec![]),
        }
    }
}

impl BlockExecutorTrait for DummyBlockExecutor {
    fn committed_block_id(&self) -> HashValue {
        HashValue::zero()
    }

    fn reset(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn execute_block(
        &self,
        _block: ExecutableBlock,
        _parent_block_id: HashValue,
        _onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<StateComputeResult> {
        Ok(StateComputeResult::new_dummy())
    }

    fn execute_and_state_checkpoint(
        &self,
        block: ExecutableBlock,
        _parent_block_id: HashValue,
        _onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<StateCheckpointOutput> {
        self.blocks_received.lock().push(block);
        Ok(StateCheckpointOutput::default())
    }

    fn ledger_update(
        &self,
        _block_id: HashValue,
        _parent_block_id: HashValue,
        _state_checkpoint_output: StateCheckpointOutput,
    ) -> ExecutorResult<StateComputeResult> {
        Ok(StateComputeResult::new_dummy())
    }

    fn commit_blocks_ext(
        &self,
        _block_ids: Vec<HashValue>,
        _ledger_info_with_sigs: LedgerInfoWithSignatures,
        _save_state_snapshots: bool,
    ) -> ExecutorResult<()> {
        Ok(())
    }

    fn finish(&self) {}
}

#[tokio::test]
#[cfg(test)]
async fn schedule_compute_should_discover_validator_txns() {
    let executor = Arc::new(DummyBlockExecutor::new());

    let execution_policy = ExecutionProxy::new(
        executor.clone(),
        Arc::new(DummyTxnNotifier {}),
        Arc::new(DummyStateSyncNotifier::new()),
        &Handle::current(),
        TransactionFilter::new(Filter::empty()),
    );

    let validator_txn_0 = ValidatorTransaction::dummy(vec![0xFF; 99]);
    let validator_txn_1 = ValidatorTransaction::dummy(vec![0xFF; 999]);

    let block = Block::new_for_testing(
        HashValue::zero(),
        BlockData::dummy_with_validator_txns(vec![
            validator_txn_0.clone(),
            validator_txn_1.clone(),
        ]),
        None,
    );

    let epoch_state = EpochState::empty();

    execution_policy.new_epoch(
        &epoch_state,
        Arc::new(PayloadManager::DirectMempool),
        Arc::new(NoOpShuffler {}),
        BlockExecutorConfigFromOnchain::new_no_block_limit(),
        Arc::new(NoOpDeduper {}),
    );

    // Ensure the dummy executor has received the txns.
    let _ = execution_policy
        .schedule_compute(&block, HashValue::zero())
        .await
        .await;

    // Get the txns from the view of the dummy executor.
    let txns = executor.blocks_received.lock()[0]
        .transactions
        .clone()
        .into_txns();

    let supposed_validator_txn_0 = txns[1].expect_valid().try_as_validator_txn().unwrap();
    let supposed_validator_txn_1 = txns[2].expect_valid().try_as_validator_txn().unwrap();
    assert_eq!(&validator_txn_0, supposed_validator_txn_0);
    assert_eq!(&validator_txn_1, supposed_validator_txn_1);
}

#[tokio::test]
async fn commit_should_discover_validator_txns() {
    let state_sync_notifier = Arc::new(DummyStateSyncNotifier::new());

    let execution_policy = ExecutionProxy::new(
        Arc::new(DummyBlockExecutor::new()),
        Arc::new(DummyTxnNotifier {}),
        state_sync_notifier.clone(),
        &tokio::runtime::Handle::current(),
        TransactionFilter::new(Filter::empty()),
    );

    let validator_txn_0 = ValidatorTransaction::dummy(vec![0xFF; 99]);
    let validator_txn_1 = ValidatorTransaction::dummy(vec![0xFF; 999]);

    let block = Block::new_for_testing(
        HashValue::zero(),
        BlockData::dummy_with_validator_txns(vec![
            validator_txn_0.clone(),
            validator_txn_1.clone(),
        ]),
        None,
    );

    // Eventually 4 txns: block metadata, sys txn 0, sys txn 1, state checkpoint.
    let state_compute_result = StateComputeResult::new_dummy_with_compute_status(vec![
            TransactionStatus::Keep(
                ExecutionStatus::Success
            );
            4
        ]);

    let blocks = vec![Arc::new(ExecutedBlock::new(block, state_compute_result))];
    let epoch_state = EpochState::empty();

    execution_policy.new_epoch(
        &epoch_state,
        Arc::new(PayloadManager::DirectMempool),
        Arc::new(NoOpShuffler {}),
        BlockExecutorConfigFromOnchain::new_no_block_limit(),
        Arc::new(NoOpDeduper {}),
    );

    let (tx, rx) = oneshot::channel::<()>();

    let callback = Box::new(
        move |_a: &[Arc<ExecutedBlock>], _b: LedgerInfoWithSignatures| {
            tx.send(()).unwrap();
        },
    );

    let _ = execution_policy
        .commit(
            blocks.as_slice(),
            LedgerInfoWithSignatures::new(LedgerInfo::dummy(), AggregateSignature::empty()),
            callback,
        )
        .await;

    // Wait until state sync is notified.
    let _ = rx.await;

    // Get all txns that state sync was notified with.
    let txns = state_sync_notifier.invocations.lock()[0].clone();

    let supposed_validator_txn_0 = txns[1].try_as_validator_txn().unwrap();
    let supposed_validator_txn_1 = txns[2].try_as_validator_txn().unwrap();
    assert_eq!(&validator_txn_0, supposed_validator_txn_0);
    assert_eq!(&validator_txn_1, supposed_validator_txn_1);
}
