use std::path::PathBuf;

use calybris_core_rs::digest::bytes_to_hex;
use calybris_core_rs::persistence::{
    checkpoint, checkpoint_with_wal, load_wal_anchor, recovery_plan, recovery_plan_against_anchor,
    recovery_plan_keyed, recovery_plan_keyed_against_anchor, restore, save_wal_anchor,
};
use calybris_core_rs::provenance::{sign_policy, verify_signed_policy_with_key, SignedPolicy};
use calybris_core_rs::receipt::{
    issue_receipt, sign_receipt, verify_receipt, verify_receipt_signature, verify_receipt_state,
    verify_receipt_wal, DecisionReceipt, ReceiptAnchors, ReceiptState, ReceiptWal,
};
use calybris_core_rs::state::{
    stateful_audit_bundle, verify_trajectory, StateChain, StateTransition, StatefulAuditBundle,
};
use calybris_core_rs::wal::{
    replay_audited_wal_keyed, verify_wal, verify_wal_against_anchor, verify_wal_keyed,
    verify_wal_keyed_against_anchor, AuditedRecord, WalAnchor, WalWriter,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use serde_json::Value;

use crate::{validate_input, PyBudgetEngine, PyKernelDecision, PyKernelInput, PyPolicySnapshot};

pyo3::create_exception!(
    calybris._core,
    CalybrisError,
    PyException,
    "Base exception for Rust-backed Calybris production APIs."
);
pyo3::create_exception!(
    calybris._core,
    ArtifactValidationError,
    CalybrisError,
    "Malformed key, JSON artifact, digest, or metadata."
);
pyo3::create_exception!(
    calybris._core,
    DecisionVerificationError,
    CalybrisError,
    "A decision failed exact deterministic replay verification."
);
pyo3::create_exception!(
    calybris._core,
    ReceiptError,
    CalybrisError,
    "Decision receipt issuance, claim, anchor, or signature failure."
);
pyo3::create_exception!(
    calybris._core,
    ProvenanceError,
    CalybrisError,
    "Signed policy provenance or pinned-key verification failure."
);
pyo3::create_exception!(
    calybris._core,
    WalError,
    CalybrisError,
    "Audited WAL integrity, locking, durability, or replay failure."
);
pyo3::create_exception!(
    calybris._core,
    PersistenceError,
    CalybrisError,
    "Snapshot, anchor, checkpoint, restore, or recovery failure."
);
pyo3::create_exception!(
    calybris._core,
    StateTrajectoryError,
    CalybrisError,
    "State trajectory linkage or replay failure."
);

fn invalid_value(error: impl std::fmt::Display) -> PyErr {
    ArtifactValidationError::new_err(error.to_string())
}

fn runtime_error(error: impl std::fmt::Display) -> PyErr {
    CalybrisError::new_err(error.to_string())
}

fn receipt_error(error: impl std::fmt::Display) -> PyErr {
    ReceiptError::new_err(error.to_string())
}

fn provenance_error(error: impl std::fmt::Display) -> PyErr {
    ProvenanceError::new_err(error.to_string())
}

fn wal_error(error: impl std::fmt::Display) -> PyErr {
    WalError::new_err(error.to_string())
}

fn persistence_error(error: impl std::fmt::Display) -> PyErr {
    PersistenceError::new_err(error.to_string())
}

fn trajectory_error(error: impl std::fmt::Display) -> PyErr {
    StateTrajectoryError::new_err(error.to_string())
}

fn decision_verification_error(error: impl std::fmt::Display) -> PyErr {
    DecisionVerificationError::new_err(error.to_string())
}

fn exact_key<const N: usize>(field: &str, value: &[u8]) -> PyResult<[u8; N]> {
    value.try_into().map_err(|_| {
        ArtifactValidationError::new_err(format!(
            "{field} must be exactly {N} bytes, found {}",
            value.len()
        ))
    })
}

fn validate_hex32(field: &str, value: &str) -> PyResult<()> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(ArtifactValidationError::new_err(format!(
            "{field} must contain exactly 64 ASCII hex characters"
        )));
    }
    Ok(())
}

fn validate_hmac_key(value: &[u8]) -> PyResult<()> {
    if value.len() < 32 {
        return Err(ArtifactValidationError::new_err(format!(
            "hmac_key must be at least 32 bytes, found {}",
            value.len()
        )));
    }
    Ok(())
}

fn verifying_key(value: &[u8]) -> PyResult<VerifyingKey> {
    let bytes = exact_key::<32>("trusted_public_key", value)?;
    VerifyingKey::from_bytes(&bytes).map_err(invalid_value)
}

fn signing_key(value: &[u8]) -> PyResult<SigningKey> {
    Ok(SigningKey::from_bytes(&exact_key::<32>(
        "signing_key",
        value,
    )?))
}

fn json_value_to_dict(py: Python<'_>, value: Value) -> PyResult<Bound<'_, PyDict>> {
    let json = serde_json::to_string(&value).map_err(runtime_error)?;
    let decoded = py.import("json")?.call_method1("loads", (json,))?;
    Ok(decoded.cast_into::<PyDict>()?)
}

fn preview(value: &str) -> String {
    value.chars().take(8).collect()
}

#[pyclass(
    name = "StateTransition",
    module = "calybris._core",
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyStateTransition {
    inner: StateTransition,
}

#[pyclass(
    name = "StatefulAuditBundle",
    module = "calybris._core",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyStatefulAuditBundle {
    inner: StatefulAuditBundle,
}

#[pymethods]
impl PyStatefulAuditBundle {
    #[getter]
    fn step(&self) -> u64 {
        self.inner.step
    }

    #[getter]
    fn state_digest_before_hex(&self) -> &str {
        &self.inner.state_digest_before_hex
    }

    #[getter]
    fn state_digest_after_hex(&self) -> &str {
        &self.inner.state_digest_after_hex
    }

    #[getter]
    fn replay_valid(&self) -> bool {
        self.inner.audit.replay_valid
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_dict(
            py,
            serde_json::to_value(&self.inner).map_err(runtime_error)?,
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "StatefulAuditBundle(step={}, replay_valid={})",
            self.inner.step, self.inner.audit.replay_valid,
        )
    }
}

#[pymethods]
impl PyStateTransition {
    #[getter]
    fn step(&self) -> u64 {
        self.inner.step
    }

    #[getter]
    fn digest_before_hex(&self) -> String {
        bytes_to_hex(&self.inner.digest_before)
    }

    #[getter]
    fn digest_after_hex(&self) -> String {
        bytes_to_hex(&self.inner.digest_after)
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let value = PyDict::new(py);
        value.set_item("step", self.inner.step)?;
        value.set_item("digest_before_hex", self.digest_before_hex())?;
        value.set_item("digest_after_hex", self.digest_after_hex())?;
        Ok(value)
    }

    fn __repr__(&self) -> String {
        format!(
            "StateTransition(step={}, before='{}...', after='{}...')",
            self.inner.step,
            preview(&self.digest_before_hex()),
            preview(&self.digest_after_hex()),
        )
    }
}

#[pyclass(name = "StateChain", module = "calybris._core")]
pub(crate) struct PyStateChain {
    inner: StateChain,
}

#[pymethods]
impl PyStateChain {
    #[new]
    fn new(initial_state: &[u8]) -> Self {
        Self {
            inner: StateChain::genesis(initial_state),
        }
    }

    #[staticmethod]
    fn genesis(initial_state: &[u8]) -> Self {
        Self::new(initial_state)
    }

    #[getter]
    fn step(&self) -> u64 {
        self.inner.step()
    }

    #[getter]
    fn last_digest_hex(&self) -> String {
        bytes_to_hex(&self.inner.last_digest())
    }

    fn advance(&mut self, next_state: &[u8]) -> PyStateTransition {
        PyStateTransition {
            inner: self.inner.advance(next_state),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "StateChain(step={}, last_digest='{}...')",
            self.inner.step(),
            preview(&self.last_digest_hex()),
        )
    }
}

#[pyclass(
    name = "ReceiptState",
    module = "calybris._core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyReceiptState {
    inner: ReceiptState,
}

#[pymethods]
impl PyReceiptState {
    #[new]
    fn new(
        step: u64,
        state_digest_before_hex: String,
        state_digest_after_hex: String,
    ) -> PyResult<Self> {
        if step == 0 {
            return Err(ArtifactValidationError::new_err("step must be at least 1"));
        }
        validate_hex32("state_digest_before_hex", &state_digest_before_hex)?;
        validate_hex32("state_digest_after_hex", &state_digest_after_hex)?;
        Ok(Self {
            inner: ReceiptState {
                step,
                state_digest_before_hex,
                state_digest_after_hex,
            },
        })
    }

    #[staticmethod]
    fn from_transition(transition: &PyStateTransition) -> Self {
        Self {
            inner: ReceiptState {
                step: transition.inner.step,
                state_digest_before_hex: bytes_to_hex(&transition.inner.digest_before),
                state_digest_after_hex: bytes_to_hex(&transition.inner.digest_after),
            },
        }
    }

    #[getter]
    fn step(&self) -> u64 {
        self.inner.step
    }

    #[getter]
    fn state_digest_before_hex(&self) -> &str {
        &self.inner.state_digest_before_hex
    }

    #[getter]
    fn state_digest_after_hex(&self) -> &str {
        &self.inner.state_digest_after_hex
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let value = PyDict::new(py);
        value.set_item("step", self.inner.step)?;
        value.set_item(
            "state_digest_before_hex",
            &self.inner.state_digest_before_hex,
        )?;
        value.set_item("state_digest_after_hex", &self.inner.state_digest_after_hex)?;
        Ok(value)
    }
}

#[pyclass(
    name = "ReceiptWal",
    module = "calybris._core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyReceiptWal {
    inner: ReceiptWal,
}

#[pymethods]
impl PyReceiptWal {
    #[new]
    fn new(sequence: u64, entry_hash: String) -> PyResult<Self> {
        if sequence == 0 {
            return Err(ArtifactValidationError::new_err(
                "sequence must be at least 1",
            ));
        }
        validate_hex32("entry_hash", &entry_hash)?;
        Ok(Self {
            inner: ReceiptWal {
                sequence,
                entry_hash,
            },
        })
    }

    #[getter]
    fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    #[getter]
    fn entry_hash(&self) -> &str {
        &self.inner.entry_hash
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let value = PyDict::new(py);
        value.set_item("sequence", self.inner.sequence)?;
        value.set_item("entry_hash", &self.inner.entry_hash)?;
        Ok(value)
    }
}

#[pyclass(name = "SignedPolicy", module = "calybris._core", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PySignedPolicy {
    inner: SignedPolicy,
}

#[pymethods]
impl PySignedPolicy {
    #[getter]
    fn policy_digest_hex(&self) -> &str {
        &self.inner.policy_digest_hex
    }

    #[getter]
    fn signer_id(&self) -> &str {
        &self.inner.signer_id
    }

    #[getter]
    fn signed_at_epoch_ms(&self) -> u64 {
        self.inner.signed_at_epoch_ms
    }

    #[getter]
    fn public_key_hex(&self) -> &str {
        &self.inner.public_key_hex
    }

    #[getter]
    fn signature_hex(&self) -> &str {
        &self.inner.signature_hex
    }

    fn verify(&self, snapshot: &PyPolicySnapshot, trusted_public_key: &[u8]) -> PyResult<()> {
        let trusted = verifying_key(trusted_public_key)?;
        verify_signed_policy_with_key(&snapshot.inner, &self.inner, &trusted)
            .map_err(provenance_error)
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(runtime_error)
    }

    #[staticmethod]
    fn from_json(value: &str) -> PyResult<Self> {
        let inner = serde_json::from_str(value).map_err(invalid_value)?;
        Ok(Self { inner })
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_dict(
            py,
            serde_json::to_value(&self.inner).map_err(runtime_error)?,
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedPolicy(signer_id={:?}, signed_at_epoch_ms={}, digest='{}...')",
            self.inner.signer_id,
            self.inner.signed_at_epoch_ms,
            preview(&self.inner.policy_digest_hex),
        )
    }
}

#[pyclass(
    name = "DecisionReceipt",
    module = "calybris._core",
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyDecisionReceipt {
    inner: DecisionReceipt,
}

#[pymethods]
impl PyDecisionReceipt {
    #[getter]
    fn schema_version(&self) -> &str {
        &self.inner.schema_version
    }

    #[getter]
    fn policy_epoch(&self) -> u64 {
        self.inner.policy_epoch
    }

    #[getter]
    fn catalog_epoch(&self) -> u64 {
        self.inner.catalog_epoch
    }

    #[getter]
    fn policy_digest_hex(&self) -> &str {
        &self.inner.policy_digest_hex
    }

    #[getter]
    fn input_digest_hex(&self) -> &str {
        &self.inner.input_digest_hex
    }

    #[getter]
    fn decision_digest_hex(&self) -> &str {
        &self.inner.decision_digest_hex
    }

    #[getter]
    fn replay_valid(&self) -> bool {
        self.inner.replay_valid
    }

    #[getter]
    fn claims_digest_hex(&self) -> &str {
        &self.inner.claims_digest_hex
    }

    #[getter]
    fn signer_id(&self) -> Option<&str> {
        self.inner
            .signature
            .as_ref()
            .map(|value| value.signer_id.as_str())
    }

    #[getter]
    fn signed_at_epoch_ms(&self) -> Option<u64> {
        self.inner
            .signature
            .as_ref()
            .map(|value| value.signed_at_epoch_ms)
    }

    #[getter]
    fn public_key_hex(&self) -> Option<&str> {
        self.inner
            .signature
            .as_ref()
            .map(|value| value.public_key_hex.as_str())
    }

    #[getter]
    fn signature_hex(&self) -> Option<&str> {
        self.inner
            .signature
            .as_ref()
            .map(|value| value.signature_hex.as_str())
    }

    #[getter]
    fn state(&self) -> Option<PyReceiptState> {
        self.inner
            .state
            .clone()
            .map(|inner| PyReceiptState { inner })
    }

    #[getter]
    fn wal(&self) -> Option<PyReceiptWal> {
        self.inner.wal.clone().map(|inner| PyReceiptWal { inner })
    }

    fn sign(
        &mut self,
        signing_key_bytes: &[u8],
        signer_id: &str,
        signed_at_epoch_ms: u64,
    ) -> PyResult<()> {
        let key = signing_key(signing_key_bytes)?;
        sign_receipt(&mut self.inner, &key, signer_id, signed_at_epoch_ms).map_err(receipt_error)
    }

    fn verify(
        &self,
        snapshot: &PyPolicySnapshot,
        input: PyKernelInput,
        decision: &PyKernelDecision,
    ) -> PyResult<()> {
        verify_receipt(
            &self.inner,
            &snapshot.inner,
            validate_input(input)?,
            &decision.inner,
        )
        .map_err(receipt_error)
    }

    fn verify_signature(&self, trusted_public_key: &[u8]) -> PyResult<()> {
        let trusted = verifying_key(trusted_public_key)?;
        verify_receipt_signature(&self.inner, Some(&trusted)).map_err(receipt_error)
    }

    fn verify_wal(&self, sequence: u64, entry_hash: &str) -> PyResult<()> {
        verify_receipt_wal(&self.inner, sequence, entry_hash).map_err(receipt_error)
    }

    fn verify_state(
        &self,
        step: u64,
        state_digest_before_hex: &str,
        state_digest_after_hex: &str,
    ) -> PyResult<()> {
        verify_receipt_state(
            &self.inner,
            step,
            state_digest_before_hex,
            state_digest_after_hex,
        )
        .map_err(receipt_error)
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner).map_err(runtime_error)
    }

    #[staticmethod]
    fn from_json(value: &str) -> PyResult<Self> {
        let inner = serde_json::from_str(value).map_err(invalid_value)?;
        Ok(Self { inner })
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_dict(
            py,
            serde_json::to_value(&self.inner).map_err(runtime_error)?,
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "DecisionReceipt(policy_epoch={}, catalog_epoch={}, signed={}, claims='{}...')",
            self.inner.policy_epoch,
            self.inner.catalog_epoch,
            self.inner.signature.is_some(),
            preview(&self.inner.claims_digest_hex),
        )
    }
}

#[pyclass(
    name = "WalAnchor",
    module = "calybris._core",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyWalAnchor {
    inner: WalAnchor,
}

#[pymethods]
impl PyWalAnchor {
    #[getter]
    fn schema_version(&self) -> &str {
        &self.inner.schema_version
    }

    #[getter]
    fn sequence(&self) -> u64 {
        self.inner.sequence
    }

    #[getter]
    fn last_hash(&self) -> &str {
        &self.inner.last_hash
    }

    #[getter]
    fn keyed(&self) -> bool {
        self.inner.keyed
    }

    fn save(&self, path: PathBuf) -> PyResult<()> {
        save_wal_anchor(&self.inner, &path).map_err(persistence_error)
    }

    #[staticmethod]
    fn load(path: PathBuf) -> PyResult<Self> {
        Ok(Self {
            inner: load_wal_anchor(&path).map_err(persistence_error)?,
        })
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        json_value_to_dict(
            py,
            serde_json::to_value(&self.inner).map_err(runtime_error)?,
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "WalAnchor(sequence={}, keyed={}, last_hash='{}...')",
            self.inner.sequence,
            self.inner.keyed,
            preview(&self.inner.last_hash),
        )
    }
}

#[pyclass(name = "WalEntry", module = "calybris._core", frozen)]
pub(crate) struct PyWalEntry {
    #[pyo3(get)]
    sequence: u64,
    #[pyo3(get)]
    previous_hash: String,
    #[pyo3(get)]
    entry_hash: String,
}

#[pymethods]
impl PyWalEntry {
    fn receipt_anchor(&self) -> PyReceiptWal {
        PyReceiptWal {
            inner: ReceiptWal {
                sequence: self.sequence,
                entry_hash: self.entry_hash.clone(),
            },
        }
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let value = PyDict::new(py);
        value.set_item("sequence", self.sequence)?;
        value.set_item("previous_hash", &self.previous_hash)?;
        value.set_item("entry_hash", &self.entry_hash)?;
        Ok(value)
    }
}

#[pyclass(name = "AuditedWal", module = "calybris._core", unsendable)]
pub(crate) struct PyAuditedWal {
    inner: Option<WalWriter<AuditedRecord<Value>>>,
}

impl PyAuditedWal {
    fn writer(&self) -> PyResult<&WalWriter<AuditedRecord<Value>>> {
        self.inner
            .as_ref()
            .ok_or_else(|| WalError::new_err("WAL writer is closed"))
    }

    fn writer_mut(&mut self) -> PyResult<&mut WalWriter<AuditedRecord<Value>>> {
        self.inner
            .as_mut()
            .ok_or_else(|| WalError::new_err("WAL writer is closed"))
    }
}

#[pymethods]
impl PyAuditedWal {
    #[new]
    #[pyo3(signature = (path, *, hmac_key=None))]
    fn new(path: PathBuf, hmac_key: Option<&[u8]>) -> PyResult<Self> {
        let inner = match hmac_key {
            Some(key) => {
                validate_hmac_key(key)?;
                WalWriter::open_keyed(&path, key)
            }
            None => WalWriter::open(&path),
        }
        .map_err(wal_error)?;
        Ok(Self { inner: Some(inner) })
    }

    #[getter]
    fn sequence(&self) -> PyResult<u64> {
        Ok(self.writer()?.sequence())
    }

    #[getter]
    fn entry_count(&self) -> PyResult<u64> {
        Ok(self.writer()?.entry_count())
    }

    #[getter]
    fn last_hash(&self) -> PyResult<String> {
        Ok(self.writer()?.last_hash().to_string())
    }

    fn append_verified(
        &mut self,
        snapshot: &PyPolicySnapshot,
        input: PyKernelInput,
        decision: &PyKernelDecision,
        metadata_json: &str,
    ) -> PyResult<PyWalEntry> {
        let metadata = serde_json::from_str(metadata_json).map_err(invalid_value)?;
        let rust_input = validate_input(input)?;
        let entry = self
            .writer_mut()?
            .append_verified_audited(&snapshot.inner, rust_input, decision.inner, metadata)
            .map_err(wal_error)?;
        Ok(PyWalEntry {
            sequence: entry.sequence,
            previous_hash: entry.previous_hash,
            entry_hash: entry.entry_hash,
        })
    }

    fn flush(&mut self) -> PyResult<()> {
        self.writer_mut()?.flush().map_err(wal_error)
    }

    fn sync(&mut self) -> PyResult<()> {
        self.writer_mut()?.sync().map_err(wal_error)
    }

    fn flush_and_sync(&mut self) -> PyResult<()> {
        self.writer_mut()?.flush_and_sync().map_err(wal_error)
    }

    fn anchor(&self) -> PyResult<PyWalAnchor> {
        Ok(PyWalAnchor {
            inner: self.writer()?.anchor(),
        })
    }

    #[pyo3(signature = (*, sync=true))]
    fn close(&mut self, sync: bool) -> PyResult<()> {
        if let Some(mut writer) = self.inner.take() {
            if sync {
                writer.flush_and_sync().map_err(wal_error)?;
            }
        }
        Ok(())
    }

    fn __repr__(&self) -> String {
        match self.inner.as_ref() {
            Some(writer) => format!(
                "AuditedWal(sequence={}, keyed={}, last_hash='{}...')",
                writer.sequence(),
                writer.anchor().keyed,
                preview(writer.last_hash()),
            ),
            None => "AuditedWal(closed=True)".to_string(),
        }
    }
}

#[pyfunction]
#[pyo3(signature = (path, *, hmac_key=None, anchor=None))]
fn verify_audited_wal(
    path: PathBuf,
    hmac_key: Option<&[u8]>,
    anchor: Option<&PyWalAnchor>,
) -> PyResult<(u64, String)> {
    if let Some(key) = hmac_key {
        validate_hmac_key(key)?;
    }
    match (hmac_key, anchor) {
        (Some(key), Some(anchor)) => {
            verify_wal_keyed_against_anchor(&path, key, &anchor.inner).map_err(wal_error)
        }
        (Some(key), None) => verify_wal_keyed(&path, key).map_err(wal_error),
        (None, Some(anchor)) => verify_wal_against_anchor(&path, &anchor.inner).map_err(wal_error),
        (None, None) => verify_wal(&path).map_err(wal_error),
    }
}

#[pyfunction]
#[pyo3(signature = (path, snapshot, *, hmac_key=None))]
fn replay_verify_audited_wal<'py>(
    py: Python<'py>,
    path: PathBuf,
    snapshot: &PyPolicySnapshot,
    hmac_key: Option<&[u8]>,
) -> PyResult<Bound<'py, PyList>> {
    if let Some(key) = hmac_key {
        validate_hmac_key(key)?;
    }
    let verdicts =
        replay_audited_wal_keyed::<Value>(&path, &snapshot.inner, hmac_key).map_err(wal_error)?;
    let values = PyList::empty(py);
    for verdict in verdicts {
        let value = PyDict::new(py);
        value.set_item("sequence", verdict.sequence)?;
        value.set_item("replay_valid", verdict.replay_valid)?;
        value.set_item("policy_digest_match", verdict.policy_digest_match)?;
        value.set_item("input_digest_match", verdict.input_digest_match)?;
        value.set_item("decision_digest_match", verdict.decision_digest_match)?;
        values.append(value)?;
    }
    Ok(values)
}

#[pyfunction]
fn verify_state_trajectory(bundles: Vec<PyStatefulAuditBundle>) -> PyResult<()> {
    let bundles = bundles
        .into_iter()
        .map(|bundle| bundle.inner)
        .collect::<Vec<_>>();
    verify_trajectory(&bundles).map_err(trajectory_error)
}

#[pyfunction]
#[pyo3(signature = (snapshot_path, wal_path, *, hmac_key=None, anchor=None))]
fn plan_recovery<'py>(
    py: Python<'py>,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
    hmac_key: Option<&[u8]>,
    anchor: Option<&PyWalAnchor>,
) -> PyResult<Bound<'py, PyDict>> {
    if let Some(key) = hmac_key {
        validate_hmac_key(key)?;
    }
    let plan = match (hmac_key, anchor) {
        (Some(key), Some(anchor)) => {
            recovery_plan_keyed_against_anchor(&snapshot_path, &wal_path, key, &anchor.inner)
        }
        (Some(key), None) => recovery_plan_keyed(&snapshot_path, &wal_path, key),
        (None, Some(anchor)) => {
            recovery_plan_against_anchor(&snapshot_path, &wal_path, &anchor.inner)
        }
        (None, None) => recovery_plan(&snapshot_path, &wal_path),
    }
    .map_err(persistence_error)?;
    let value = PyDict::new(py);
    value.set_item("total_wal_entries", plan.total_wal_entries)?;
    value.set_item("entries_to_replay", plan.entries_to_replay)?;
    value.set_item("wal_high_watermark", plan.wal_high_watermark)?;
    value.set_item(
        "snapshot",
        json_value_to_dict(
            py,
            serde_json::to_value(&plan.snapshot).map_err(runtime_error)?,
        )?,
    )?;
    Ok(value)
}

#[pyfunction]
fn public_key_from_signing_key<'py>(
    py: Python<'py>,
    signing_key_bytes: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = signing_key(signing_key_bytes)?;
    Ok(PyBytes::new(py, key.verifying_key().as_bytes()))
}

#[pymethods]
impl PyPolicySnapshot {
    fn sign_policy(
        &self,
        signing_key_bytes: &[u8],
        signer_id: &str,
        signed_at_epoch_ms: u64,
    ) -> PyResult<PySignedPolicy> {
        let key = signing_key(signing_key_bytes)?;
        Ok(PySignedPolicy {
            inner: sign_policy(&self.inner, &key, signer_id, signed_at_epoch_ms),
        })
    }

    #[pyo3(signature = (input, decision, *, state=None, wal=None))]
    fn issue_receipt(
        &self,
        input: PyKernelInput,
        decision: &PyKernelDecision,
        state: Option<&PyReceiptState>,
        wal: Option<&PyReceiptWal>,
    ) -> PyResult<PyDecisionReceipt> {
        let inner = issue_receipt(
            &self.inner,
            validate_input(input)?,
            &decision.inner,
            ReceiptAnchors {
                state: state.map(|value| value.inner.clone()),
                wal: wal.map(|value| value.inner.clone()),
            },
        )
        .map_err(receipt_error)?;
        Ok(PyDecisionReceipt { inner })
    }

    fn stateful_audit_bundle(
        &self,
        input: PyKernelInput,
        decision: &PyKernelDecision,
        transition: &PyStateTransition,
    ) -> PyResult<PyStatefulAuditBundle> {
        let bundle = stateful_audit_bundle(
            &self.inner,
            validate_input(input)?,
            &decision.inner,
            &transition.inner,
        )
        .map_err(decision_verification_error)?;
        Ok(PyStatefulAuditBundle { inner: bundle })
    }
}

#[pymethods]
impl PyBudgetEngine {
    fn checkpoint<'py>(&self, py: Python<'py>, path: PathBuf) -> PyResult<Bound<'py, PyDict>> {
        let snapshot = checkpoint(&self.inner, &path).map_err(persistence_error)?;
        json_value_to_dict(py, serde_json::to_value(snapshot).map_err(runtime_error)?)
    }

    fn checkpoint_with_wal<'py>(
        &self,
        py: Python<'py>,
        path: PathBuf,
        wal_sequence: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let snapshot =
            checkpoint_with_wal(&self.inner, &path, wal_sequence).map_err(persistence_error)?;
        json_value_to_dict(py, serde_json::to_value(snapshot).map_err(runtime_error)?)
    }

    fn restore<'py>(&self, py: Python<'py>, path: PathBuf) -> PyResult<Bound<'py, PyDict>> {
        let snapshot = restore(&self.inner, &path).map_err(persistence_error)?;
        json_value_to_dict(py, serde_json::to_value(snapshot).map_err(runtime_error)?)
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("CalybrisError", py.get_type::<CalybrisError>())?;
    m.add(
        "ArtifactValidationError",
        py.get_type::<ArtifactValidationError>(),
    )?;
    m.add(
        "DecisionVerificationError",
        py.get_type::<DecisionVerificationError>(),
    )?;
    m.add("ReceiptError", py.get_type::<ReceiptError>())?;
    m.add("ProvenanceError", py.get_type::<ProvenanceError>())?;
    m.add("WalError", py.get_type::<WalError>())?;
    m.add("PersistenceError", py.get_type::<PersistenceError>())?;
    m.add(
        "StateTrajectoryError",
        py.get_type::<StateTrajectoryError>(),
    )?;
    m.add_class::<PyStateTransition>()?;
    m.add_class::<PyStatefulAuditBundle>()?;
    m.add_class::<PyStateChain>()?;
    m.add_class::<PyReceiptState>()?;
    m.add_class::<PyReceiptWal>()?;
    m.add_class::<PySignedPolicy>()?;
    m.add_class::<PyDecisionReceipt>()?;
    m.add_class::<PyWalAnchor>()?;
    m.add_class::<PyWalEntry>()?;
    m.add_class::<PyAuditedWal>()?;
    m.add_function(wrap_pyfunction!(verify_audited_wal, m)?)?;
    m.add_function(wrap_pyfunction!(replay_verify_audited_wal, m)?)?;
    m.add_function(wrap_pyfunction!(verify_state_trajectory, m)?)?;
    m.add_function(wrap_pyfunction!(plan_recovery, m)?)?;
    m.add_function(wrap_pyfunction!(public_key_from_signing_key, m)?)?;
    Ok(())
}
