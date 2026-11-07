use crate::{
    verify_did_document_proof, verify_did_document_proof_standard_value, CryptoError, DidDocument,
};
use futures::channel::oneshot;
use serde_json::Value;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, OnceLock},
    thread::{self, JoinHandle},
};
use thiserror::Error;

const WORKER_COUNT: usize = 4;
const QUEUE_CAPACITY: usize = 8;
const WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;
const WORKER_NAME: &str = "oan-did-document-proof-verifier";
const VERIFIER_PANICKED: &str = "verifier thread panicked";

static EXECUTOR: OnceLock<Result<DidDocumentVerificationExecutor, String>> = OnceLock::new();

#[derive(Debug)]
pub struct VerifiedWireDidDocument {
    raw: Arc<Value>,
}

impl VerifiedWireDidDocument {
    pub fn as_value(&self) -> &Value {
        self.raw.as_ref()
    }

    pub fn into_value(self) -> Value {
        Arc::try_unwrap(self.raw).unwrap_or_else(|raw| raw.as_ref().clone())
    }
}

#[derive(Debug, Error)]
pub enum CompatibleDidDocumentProofError {
    #[error("{0}")]
    Deserialization(serde_json::Error),
    #[error("did_document_proof_invalid: {standard}; fallback: {fallback}")]
    Verification {
        standard: CryptoError,
        fallback: CryptoError,
    },
}

enum VerificationJob {
    Standard {
        document: Arc<Value>,
        result: oneshot::Sender<Result<(), CryptoError>>,
    },
    Compatible {
        document: Arc<Value>,
        result: oneshot::Sender<Result<VerifiedWireDidDocument, CompatibleDidDocumentProofError>>,
    },
}

struct DidDocumentVerificationExecutor {
    sender: Option<flume::Sender<VerificationJob>>,
    workers: Vec<JoinHandle<()>>,
}

impl DidDocumentVerificationExecutor {
    fn new() -> Result<Self, String> {
        Self::with_capacity(WORKER_COUNT, QUEUE_CAPACITY)
    }

    fn with_capacity(worker_count: usize, queue_capacity: usize) -> Result<Self, String> {
        let (sender, receiver) = flume::bounded(queue_capacity);
        let mut workers = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let worker_receiver = receiver.clone();
            let worker = thread::Builder::new()
                .name(format!("{WORKER_NAME}-{index}"))
                .stack_size(WORKER_STACK_SIZE)
                .spawn(move || worker_loop(worker_receiver));
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    drop(sender);
                    drop(receiver);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error.to_string());
                }
            }
        }
        drop(receiver);
        Ok(Self {
            sender: Some(sender),
            workers,
        })
    }

    fn sender(&self) -> Option<&flume::Sender<VerificationJob>> {
        self.sender.as_ref()
    }

    async fn verify_standard(&self, document: Arc<Value>) -> Result<(), CryptoError> {
        let (result_tx, result_rx) = oneshot::channel();
        let job = VerificationJob::Standard {
            document: Arc::clone(&document),
            result: result_tx,
        };
        let Some(sender) = self.sender() else {
            return verify_standard_one_off_async(document).await;
        };
        if sender.send_async(job).await.is_err() {
            return verify_standard_one_off_async(document).await;
        }
        match result_rx.await {
            Ok(result) => result,
            Err(_) => verify_standard_one_off_async(document).await,
        }
    }

    fn verify_standard_blocking(&self, document: Arc<Value>) -> Result<(), CryptoError> {
        let (result_tx, result_rx) = oneshot::channel();
        let job = VerificationJob::Standard {
            document: Arc::clone(&document),
            result: result_tx,
        };
        let Some(sender) = self.sender() else {
            return verify_standard_one_off_blocking(document);
        };
        if sender.send(job).is_err() {
            return verify_standard_one_off_blocking(document);
        }
        match futures::executor::block_on(result_rx) {
            Ok(result) => result,
            Err(_) => verify_standard_one_off_blocking(document),
        }
    }

    async fn verify_compatible(
        &self,
        document: Arc<Value>,
    ) -> Result<VerifiedWireDidDocument, CompatibleDidDocumentProofError> {
        let (result_tx, result_rx) = oneshot::channel();
        let job = VerificationJob::Compatible {
            document: Arc::clone(&document),
            result: result_tx,
        };
        let Some(sender) = self.sender() else {
            return verify_compatible_one_off_async(document).await;
        };
        if sender.send_async(job).await.is_err() {
            return verify_compatible_one_off_async(document).await;
        }
        match result_rx.await {
            Ok(result) => result,
            Err(_) => verify_compatible_one_off_async(document).await,
        }
    }
}

impl Drop for DidDocumentVerificationExecutor {
    fn drop(&mut self) {
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn worker_loop(receiver: flume::Receiver<VerificationJob>) {
    while let Ok(job) = receiver.recv() {
        match job {
            VerificationJob::Standard { document, result } => {
                let _ = result.send(run_standard(document.as_ref()));
            }
            VerificationJob::Compatible { document, result } => {
                let _ = result.send(run_compatible(document));
            }
        }
    }
}

fn run_standard(document: &Value) -> Result<(), CryptoError> {
    catch_unwind(AssertUnwindSafe(|| {
        futures::executor::block_on(verify_did_document_proof_standard_value(document.clone()))
    }))
    .unwrap_or_else(|_| {
        Err(CryptoError::StandardDataIntegrity(
            VERIFIER_PANICKED.to_owned(),
        ))
    })
}

fn run_compatible(
    document: Arc<Value>,
) -> Result<VerifiedWireDidDocument, CompatibleDidDocumentProofError> {
    match run_standard(document.as_ref()) {
        Ok(()) => Ok(VerifiedWireDidDocument { raw: document }),
        Err(standard) => run_compatible_fallback(document, standard),
    }
}

fn run_compatible_fallback(
    document: Arc<Value>,
    standard: CryptoError,
) -> Result<VerifiedWireDidDocument, CompatibleDidDocumentProofError> {
    let typed: DidDocument = serde_json::from_value(document.as_ref().clone())
        .map_err(CompatibleDidDocumentProofError::Deserialization)?;
    let fallback = catch_unwind(AssertUnwindSafe(|| verify_did_document_proof(&typed)))
        .unwrap_or_else(|_| {
            Err(CryptoError::StandardDataIntegrity(
                VERIFIER_PANICKED.to_owned(),
            ))
        });
    match fallback {
        Ok(()) => Ok(VerifiedWireDidDocument { raw: document }),
        Err(fallback) => Err(CompatibleDidDocumentProofError::Verification { standard, fallback }),
    }
}

fn shared_executor() -> Result<&'static DidDocumentVerificationExecutor, &'static str> {
    match EXECUTOR.get_or_init(DidDocumentVerificationExecutor::new) {
        Ok(executor) => Ok(executor),
        Err(error) => Err(error.as_str()),
    }
}

pub async fn verify_did_document_proof_standard_value_isolated(
    document: Value,
) -> Result<(), CryptoError> {
    let document = Arc::new(document);
    match shared_executor() {
        Ok(executor) => executor.verify_standard(document).await,
        Err(_) => verify_standard_one_off_async(document).await,
    }
}

pub async fn verify_did_document_proof_compatible_value_isolated(
    document: Value,
) -> Result<VerifiedWireDidDocument, CompatibleDidDocumentProofError> {
    let document = Arc::new(document);
    match shared_executor() {
        Ok(executor) => executor.verify_compatible(document).await,
        Err(_) => verify_compatible_one_off_async(document).await,
    }
}

pub fn verify_did_document_proof_standard_blocking(
    document: &DidDocument,
) -> Result<(), CryptoError> {
    verify_did_document_proof_standard_value_blocking(serde_json::to_value(document)?)
}

pub fn verify_did_document_proof_standard_value_blocking(
    document: Value,
) -> Result<(), CryptoError> {
    let document = Arc::new(document);
    match shared_executor() {
        Ok(executor) => executor.verify_standard_blocking(document),
        Err(_) => verify_standard_one_off_blocking(document),
    }
}

async fn verify_standard_one_off_async(document: Arc<Value>) -> Result<(), CryptoError> {
    let (result_tx, result_rx) = oneshot::channel();
    thread::Builder::new()
        .name(WORKER_NAME.to_owned())
        .stack_size(WORKER_STACK_SIZE)
        .spawn(move || {
            let _ = result_tx.send(run_standard(document.as_ref()));
        })
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?;
    result_rx.await.unwrap_or_else(|_| {
        Err(CryptoError::StandardDataIntegrity(
            VERIFIER_PANICKED.to_owned(),
        ))
    })
}

fn verify_standard_one_off_blocking(document: Arc<Value>) -> Result<(), CryptoError> {
    thread::Builder::new()
        .name(WORKER_NAME.to_owned())
        .stack_size(WORKER_STACK_SIZE)
        .spawn(move || run_standard(document.as_ref()))
        .map_err(|error| CryptoError::StandardDataIntegrity(error.to_string()))?
        .join()
        .map_err(|_| CryptoError::StandardDataIntegrity(VERIFIER_PANICKED.to_owned()))?
}

async fn verify_compatible_one_off_async(
    document: Arc<Value>,
) -> Result<VerifiedWireDidDocument, CompatibleDidDocumentProofError> {
    let (result_tx, result_rx) = oneshot::channel();
    let fallback_document = Arc::clone(&document);
    let worker = thread::Builder::new()
        .name(WORKER_NAME.to_owned())
        .stack_size(WORKER_STACK_SIZE)
        .spawn(move || {
            let _ = result_tx.send(run_compatible(document));
        });
    if let Err(error) = worker {
        return run_compatible_fallback(
            fallback_document,
            CryptoError::StandardDataIntegrity(error.to_string()),
        );
    }
    match result_rx.await {
        Ok(result) => result,
        Err(_) => run_compatible_fallback(
            fallback_document,
            CryptoError::StandardDataIntegrity(VERIFIER_PANICKED.to_owned()),
        ),
    }
}

