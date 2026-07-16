use calybris_core_rs::budget::{
    BudgetEngine, BudgetReservation, BudgetSettlement, ConservationStatus, TopUpResult,
};
use calybris_core_rs::finance::{certify_ledger, prove_conservation, MICROCENTS_PER_CENT};
use calybris_core_rs::kernel::{
    KernelDecision, KernelInput, KernelModel, PolicySnapshot, ALL_PROVIDERS, ALL_REGIONS,
};
use calybris_core_rs::proof::seal;
use calybris_core_rs::verify::{
    audit_bundle, counterfactual_utility, snapshot_fingerprint, verified_audit_bundle,
    verify_decision, VerifyResult,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

mod production;

#[pyclass(name = "KernelModel", module = "calybris._core", from_py_object)]
#[derive(Clone)]
struct PyKernelModel {
    #[pyo3(get, set)]
    model_id: u32,
    #[pyo3(get, set)]
    provider_id: u16,
    #[pyo3(get, set)]
    quality_bps: u16,
    #[pyo3(get, set)]
    risk_ceiling_bps: u16,
    #[pyo3(get, set)]
    enabled: u8,
    #[pyo3(get, set)]
    p95_latency_ms: u32,
    #[pyo3(get, set)]
    capabilities: u64,
    #[pyo3(get, set)]
    region_mask: u64,
    #[pyo3(get, set)]
    input_cost_microunits_per_million_tokens: u64,
    #[pyo3(get, set)]
    output_cost_microunits_per_million_tokens: u64,
}

#[pymethods]
impl PyKernelModel {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        model_id: u32,
        provider_id: u16,
        quality_bps: u16,
        risk_ceiling_bps: u16,
        enabled: u8,
        p95_latency_ms: u32,
        capabilities: u64,
        region_mask: u64,
        input_cost_microunits_per_million_tokens: u64,
        output_cost_microunits_per_million_tokens: u64,
    ) -> Self {
        Self {
            model_id,
            provider_id,
            quality_bps,
            risk_ceiling_bps,
            enabled,
            p95_latency_ms,
            capabilities,
            region_mask,
            input_cost_microunits_per_million_tokens,
            output_cost_microunits_per_million_tokens,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "KernelModel(model_id={}, provider_id={}, quality_bps={}, enabled={})",
            self.model_id, self.provider_id, self.quality_bps, self.enabled
        )
    }

    fn __eq__(&self, other: &PyKernelModel) -> bool {
        self.model_id == other.model_id
            && self.provider_id == other.provider_id
            && self.quality_bps == other.quality_bps
            && self.risk_ceiling_bps == other.risk_ceiling_bps
            && self.enabled == other.enabled
            && self.p95_latency_ms == other.p95_latency_ms
            && self.capabilities == other.capabilities
            && self.region_mask == other.region_mask
            && self.input_cost_microunits_per_million_tokens
                == other.input_cost_microunits_per_million_tokens
            && self.output_cost_microunits_per_million_tokens
                == other.output_cost_microunits_per_million_tokens
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("model_id", self.model_id)?;
        d.set_item("provider_id", self.provider_id)?;
        d.set_item("quality_bps", self.quality_bps)?;
        d.set_item("risk_ceiling_bps", self.risk_ceiling_bps)?;
        d.set_item("enabled", self.enabled)?;
        d.set_item("p95_latency_ms", self.p95_latency_ms)?;
        d.set_item("capabilities", self.capabilities)?;
        d.set_item("region_mask", self.region_mask)?;
        d.set_item(
            "input_cost_microunits_per_million_tokens",
            self.input_cost_microunits_per_million_tokens,
        )?;
        d.set_item(
            "output_cost_microunits_per_million_tokens",
            self.output_cost_microunits_per_million_tokens,
        )?;
        Ok(d)
    }
}

impl From<PyKernelModel> for KernelModel {
    fn from(m: PyKernelModel) -> Self {
        Self {
            model_id: m.model_id,
            provider_id: m.provider_id,
            quality_bps: m.quality_bps,
            risk_ceiling_bps: m.risk_ceiling_bps,
            enabled: m.enabled,
            p95_latency_ms: m.p95_latency_ms,
            capabilities: m.capabilities,
            region_mask: m.region_mask,
            input_cost_microunits_per_million_tokens: m.input_cost_microunits_per_million_tokens,
            output_cost_microunits_per_million_tokens: m.output_cost_microunits_per_million_tokens,
        }
    }
}

impl From<&KernelModel> for PyKernelModel {
    fn from(m: &KernelModel) -> Self {
        Self {
            model_id: m.model_id,
            provider_id: m.provider_id,
            quality_bps: m.quality_bps,
            risk_ceiling_bps: m.risk_ceiling_bps,
            enabled: m.enabled,
            p95_latency_ms: m.p95_latency_ms,
            capabilities: m.capabilities,
            region_mask: m.region_mask,
            input_cost_microunits_per_million_tokens: m.input_cost_microunits_per_million_tokens,
            output_cost_microunits_per_million_tokens: m.output_cost_microunits_per_million_tokens,
        }
    }
}

#[pyclass(name = "KernelInput", module = "calybris._core", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct PyKernelInput {
    #[pyo3(get, set)]
    request_sequence: u64,
    #[pyo3(get, set)]
    requested_model_id: u32,
    #[pyo3(get, set)]
    input_tokens: u32,
    #[pyo3(get, set)]
    output_tokens: u32,
    #[pyo3(get, set)]
    business_value_microunits: i64,
    #[pyo3(get, set)]
    budget_limit_microunits: u64,
    #[pyo3(get, set)]
    risk_bps: u16,
    #[pyo3(get, set)]
    confidence_bps: u16,
    #[pyo3(get, set)]
    minimum_quality_bps: u16,
    #[pyo3(get, set)]
    max_p95_latency_ms: u32,
    #[pyo3(get, set)]
    required_capabilities: u64,
    #[pyo3(get, set)]
    allowed_provider_mask: u64,
    #[pyo3(get, set)]
    required_region_mask: u64,
}

#[pymethods]
impl PyKernelInput {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        request_sequence: u64,
        requested_model_id: u32,
        input_tokens: u32,
        output_tokens: u32,
        business_value_microunits: i64,
        budget_limit_microunits: u64,
        risk_bps: u16,
        confidence_bps: u16,
        minimum_quality_bps: u16,
        max_p95_latency_ms: u32,
        required_capabilities: u64,
        allowed_provider_mask: u64,
        required_region_mask: u64,
    ) -> PyResult<Self> {
        let py_input = Self {
            request_sequence,
            requested_model_id,
            input_tokens,
            output_tokens,
            business_value_microunits,
            budget_limit_microunits,
            risk_bps,
            confidence_bps,
            minimum_quality_bps,
            max_p95_latency_ms,
            required_capabilities,
            allowed_provider_mask,
            required_region_mask,
        };
        KernelInput::from(py_input)
            .validate()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(py_input)
    }

    fn __repr__(&self) -> String {
        format!(
            "KernelInput(seq={}, model={}, tokens={}/{})",
            self.request_sequence, self.requested_model_id, self.input_tokens, self.output_tokens,
        )
    }

    fn __eq__(&self, other: &PyKernelInput) -> bool {
        self.request_sequence == other.request_sequence
            && self.requested_model_id == other.requested_model_id
            && self.input_tokens == other.input_tokens
            && self.output_tokens == other.output_tokens
            && self.business_value_microunits == other.business_value_microunits
            && self.budget_limit_microunits == other.budget_limit_microunits
            && self.risk_bps == other.risk_bps
            && self.confidence_bps == other.confidence_bps
            && self.minimum_quality_bps == other.minimum_quality_bps
            && self.max_p95_latency_ms == other.max_p95_latency_ms
            && self.required_capabilities == other.required_capabilities
            && self.allowed_provider_mask == other.allowed_provider_mask
            && self.required_region_mask == other.required_region_mask
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("request_sequence", self.request_sequence)?;
        d.set_item("requested_model_id", self.requested_model_id)?;
        d.set_item("input_tokens", self.input_tokens)?;
        d.set_item("output_tokens", self.output_tokens)?;
        d.set_item("business_value_microunits", self.business_value_microunits)?;
        d.set_item("budget_limit_microunits", self.budget_limit_microunits)?;
        d.set_item("risk_bps", self.risk_bps)?;
        d.set_item("confidence_bps", self.confidence_bps)?;
        d.set_item("minimum_quality_bps", self.minimum_quality_bps)?;
        d.set_item("max_p95_latency_ms", self.max_p95_latency_ms)?;
        d.set_item("required_capabilities", self.required_capabilities)?;
        d.set_item("allowed_provider_mask", self.allowed_provider_mask)?;
        d.set_item("required_region_mask", self.required_region_mask)?;
        Ok(d)
    }
}

impl From<PyKernelInput> for KernelInput {
    fn from(i: PyKernelInput) -> Self {
        Self {
            request_sequence: i.request_sequence,
            requested_model_id: i.requested_model_id,
            input_tokens: i.input_tokens,
            output_tokens: i.output_tokens,
            business_value_microunits: i.business_value_microunits,
            budget_limit_microunits: i.budget_limit_microunits,
            risk_bps: i.risk_bps,
            confidence_bps: i.confidence_bps,
            minimum_quality_bps: i.minimum_quality_bps,
            max_p95_latency_ms: i.max_p95_latency_ms,
            required_capabilities: i.required_capabilities,
            allowed_provider_mask: i.allowed_provider_mask,
            required_region_mask: i.required_region_mask,
        }
    }
}

#[pyclass(name = "KernelDecision", module = "calybris._core", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct PyKernelDecision {
    pub(crate) inner: KernelDecision,
}

#[pymethods]
impl PyKernelDecision {
    #[getter]
    fn request_sequence(&self) -> u64 {
        self.inner.request_sequence
    }

    #[getter]
    fn action(&self) -> String {
        self.inner.action.to_string()
    }

    #[getter]
    fn action_code(&self) -> u8 {
        self.inner.action as u8
    }

    #[getter]
    fn reason(&self) -> String {
        self.inner.reason.to_string()
    }

    #[getter]
    fn reason_code(&self) -> u16 {
        self.inner.reason as u16
    }

    #[getter]
    fn selected_model_id(&self) -> u32 {
        self.inner.selected_model_id
    }

    #[getter]
    fn selected_model_index(&self) -> u16 {
        self.inner.selected_model_index
    }

    #[getter]
    fn estimated_cost_microunits(&self) -> u64 {
        self.inner.estimated_cost_microunits
    }

    #[getter]
    fn expected_utility_microunits(&self) -> i64 {
        self.inner.expected_utility_microunits
    }

    #[getter]
    fn counterfactual_model_id(&self) -> u32 {
        self.inner.counterfactual_model_id
    }

    #[getter]
    fn counterfactual_utility_microunits(&self) -> i64 {
        self.inner.counterfactual_utility_microunits
    }

    #[getter]
    fn evaluated_models(&self) -> u16 {
        self.inner.evaluated_models
    }

    #[getter]
    fn eligible_models(&self) -> u16 {
        self.inner.eligible_models
    }

    #[getter]
    fn policy_epoch(&self) -> u64 {
        self.inner.policy_epoch
    }

    #[getter]
    fn catalog_epoch(&self) -> u64 {
        self.inner.catalog_epoch
    }

    fn is_executable(&self) -> bool {
        self.inner.is_executable()
    }

    fn is_rejected(&self) -> bool {
        self.inner.is_rejected()
    }

    fn is_requested_execution(&self) -> bool {
        self.inner.is_requested_execution()
    }

    fn is_substitution(&self) -> bool {
        self.inner.is_substitution()
    }

    fn __repr__(&self) -> String {
        format!(
            "KernelDecision(seq={}, action='{}', model={}, reason='{}')",
            self.inner.request_sequence,
            self.inner.action,
            self.inner.selected_model_id,
            self.inner.reason,
        )
    }

    fn __eq__(&self, other: &PyKernelDecision) -> bool {
        self.inner == other.inner
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("request_sequence", self.inner.request_sequence)?;
        d.set_item("action", self.inner.action.to_string())?;
        d.set_item("action_code", self.inner.action as u8)?;
        d.set_item("reason", self.inner.reason.to_string())?;
        d.set_item("reason_code", self.inner.reason as u16)?;
        d.set_item("selected_model_id", self.inner.selected_model_id)?;
        d.set_item("selected_model_index", self.inner.selected_model_index)?;
        d.set_item(
            "estimated_cost_microunits",
            self.inner.estimated_cost_microunits,
        )?;
        d.set_item(
            "expected_utility_microunits",
            self.inner.expected_utility_microunits,
        )?;
        d.set_item(
            "counterfactual_model_id",
            self.inner.counterfactual_model_id,
        )?;
        d.set_item(
            "counterfactual_utility_microunits",
            self.inner.counterfactual_utility_microunits,
        )?;
        d.set_item("evaluated_models", self.inner.evaluated_models)?;
        d.set_item("eligible_models", self.inner.eligible_models)?;
        d.set_item("policy_epoch", self.inner.policy_epoch)?;
        d.set_item("catalog_epoch", self.inner.catalog_epoch)?;
        Ok(d)
    }
}

impl From<KernelDecision> for PyKernelDecision {
    fn from(inner: KernelDecision) -> Self {
        Self { inner }
    }
}

#[pyclass(name = "PolicySnapshot", module = "calybris._core")]
pub(crate) struct PyPolicySnapshot {
    pub(crate) inner: PolicySnapshot,
}

#[pymethods]
impl PyPolicySnapshot {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        policy_epoch: u64,
        catalog_epoch: u64,
        hard_risk_limit_bps: u16,
        minimum_confidence_bps: u16,
        risk_penalty_multiplier_bps: u16,
        latency_penalty_microunits_per_ms: u64,
        models: Vec<PyKernelModel>,
    ) -> PyResult<Self> {
        let models = models.into_iter().map(KernelModel::from).collect();
        PolicySnapshot::try_new(
            policy_epoch,
            catalog_epoch,
            hard_risk_limit_bps,
            minimum_confidence_bps,
            risk_penalty_multiplier_bps,
            latency_penalty_microunits_per_ms,
            models,
        )
        .map(|inner| Self { inner })
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "PolicySnapshot(policy_epoch={}, catalog_epoch={}, models={})",
            self.inner.policy_epoch,
            self.inner.catalog_epoch,
            self.inner.models().len(),
        )
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
    fn hard_risk_limit_bps(&self) -> u16 {
        self.inner.hard_risk_limit_bps
    }

    #[getter]
    fn minimum_confidence_bps(&self) -> u16 {
        self.inner.minimum_confidence_bps
    }

    #[getter]
    fn risk_penalty_multiplier_bps(&self) -> u16 {
        self.inner.risk_penalty_multiplier_bps
    }

    #[getter]
    fn latency_penalty_microunits_per_ms(&self) -> u64 {
        self.inner.latency_penalty_microunits_per_ms
    }

    fn model_count(&self) -> usize {
        self.inner.models().len()
    }

    fn models(&self) -> Vec<PyKernelModel> {
        self.inner
            .models()
            .iter()
            .map(PyKernelModel::from)
            .collect()
    }

    fn fingerprint(&self) -> String {
        snapshot_fingerprint(&self.inner)
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("policy_epoch", self.inner.policy_epoch)?;
        d.set_item("catalog_epoch", self.inner.catalog_epoch)?;
        d.set_item("hard_risk_limit_bps", self.inner.hard_risk_limit_bps)?;
        d.set_item("minimum_confidence_bps", self.inner.minimum_confidence_bps)?;
        d.set_item(
            "risk_penalty_multiplier_bps",
            self.inner.risk_penalty_multiplier_bps,
        )?;
        d.set_item(
            "latency_penalty_microunits_per_ms",
            self.inner.latency_penalty_microunits_per_ms,
        )?;
        d.set_item("model_count", self.inner.models().len())?;
        d.set_item("fingerprint", snapshot_fingerprint(&self.inner))?;
        Ok(d)
    }

    fn prescribe(&self, input: PyKernelInput) -> PyResult<PyKernelDecision> {
        let rust_input = KernelInput::from(input);
        rust_input
            .validate()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(self.inner.prescribe(rust_input).into())
    }

    fn prescribe_with_trace<'py>(
        &self,
        py: Python<'py>,
        input: PyKernelInput,
    ) -> PyResult<(PyKernelDecision, Bound<'py, PyDict>)> {
        let rust_input = KernelInput::from(input);
        rust_input
            .validate()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let (decision, trace) = self.inner.prescribe_with_trace(rust_input);
        Ok((decision.into(), decision_trace_to_dict(py, &trace)?))
    }

    fn utility_for_model(&self, input: PyKernelInput, model_id: u32) -> PyResult<Option<i64>> {
        let rust_input = validate_input(input)?;
        Ok(self.inner.utility_for_model(rust_input, model_id))
    }

    fn counterfactual_utility(&self, input: PyKernelInput, model_id: u32) -> PyResult<Option<i64>> {
        let rust_input = validate_input(input)?;
        Ok(counterfactual_utility(&self.inner, rust_input, model_id))
    }

    fn proof_envelope<'py>(
        &self,
        py: Python<'py>,
        input: PyKernelInput,
        decision: &PyKernelDecision,
    ) -> PyResult<Bound<'py, PyDict>> {
        let rust_input = validate_input(input)?;
        let envelope = seal(&self.inner, rust_input, &decision.inner);
        let d = PyDict::new(py);
        d.set_item("proof_version", envelope.proof_version)?;
        d.set_item("policy_digest_hex", envelope.policy_digest_hex)?;
        d.set_item("input_digest_hex", envelope.input_digest_hex)?;
        d.set_item("decision_digest_hex", envelope.decision_digest_hex)?;
        d.set_item("replay_valid", envelope.replay_valid)?;
        d.set_item("wal_sequence", envelope.wal_sequence)?;
        d.set_item("wal_entry_hash", envelope.wal_entry_hash)?;
        d.set_item("budget_snapshot_version", envelope.budget_snapshot_version)?;
        d.set_item("ledger_digest_hex", envelope.ledger_digest_hex)?;
        d.set_item("action", envelope.action)?;
        d.set_item("reason", envelope.reason)?;
        d.set_item("selected_model_id", envelope.selected_model_id)?;
        d.set_item("counterfactual_model_id", envelope.counterfactual_model_id)?;
        d.set_item(
            "estimated_cost_microunits",
            envelope.estimated_cost_microunits,
        )?;
        d.set_item(
            "expected_utility_microunits",
            envelope.expected_utility_microunits,
        )?;
        Ok(d)
    }

    fn prescribe_batch(
        &self,
        py: Python<'_>,
        inputs: Vec<PyKernelInput>,
    ) -> PyResult<Vec<PyKernelDecision>> {
        let rust_inputs = inputs
            .into_iter()
            .map(validate_input)
            .collect::<PyResult<Vec<_>>>()?;
        let decisions = py.detach(|| self.inner.prescribe_batch(&rust_inputs));
        Ok(decisions.into_iter().map(PyKernelDecision::from).collect())
    }

    /// Returns a dict with `status` plus diagnostic fields for mismatch variants.
    fn verify<'py>(
        &self,
        py: Python<'py>,
        input: PyKernelInput,
        decision: &PyKernelDecision,
    ) -> PyResult<Bound<'py, PyDict>> {
        let input = validate_input(input)?;
        let d = PyDict::new(py);
        match verify_decision(&self.inner, input, &decision.inner) {
            VerifyResult::Valid => {
                d.set_item("status", "valid")?;
            }
            VerifyResult::Mismatch { expected, actual } => {
                d.set_item("status", "mismatch")?;
                d.set_item("expected_action", expected.action.to_string())?;
                d.set_item("actual_action", actual.action.to_string())?;
                d.set_item("expected_model_id", expected.selected_model_id)?;
                d.set_item("actual_model_id", actual.selected_model_id)?;
                d.set_item("expected_reason", expected.reason.to_string())?;
                d.set_item("actual_reason", actual.reason.to_string())?;
            }
            VerifyResult::DigestMismatch {
                expected_hex,
                actual_hex,
            } => {
                d.set_item("status", "digest_mismatch")?;
                d.set_item("expected_hex", expected_hex)?;
                d.set_item("actual_hex", actual_hex)?;
            }
        }
        Ok(d)
    }

    /// Returns `"valid"`, `"mismatch"`, or `"digest_mismatch"` — cheap status check.
    fn verify_status(
        &self,
        input: PyKernelInput,
        decision: &PyKernelDecision,
    ) -> PyResult<&'static str> {
        let input = validate_input(input)?;
        Ok(match verify_decision(&self.inner, input, &decision.inner) {
            VerifyResult::Valid => "valid",
            VerifyResult::Mismatch { .. } => "mismatch",
            VerifyResult::DigestMismatch { .. } => "digest_mismatch",
        })
    }

    fn audit_bundle<'py>(
        &self,
        py: Python<'py>,
        input: PyKernelInput,
        decision: &PyKernelDecision,
    ) -> PyResult<Bound<'py, PyDict>> {
        let rust_input = validate_input(input)?;
        let bundle = audit_bundle(&self.inner, rust_input, &decision.inner);
        audit_bundle_to_dict(py, &bundle)
    }

    /// Like `audit_bundle` but raises `ValueError` when replay fails — fail-closed audit path.
    fn verified_audit_bundle<'py>(
        &self,
        py: Python<'py>,
        input: PyKernelInput,
        decision: &PyKernelDecision,
    ) -> PyResult<Bound<'py, PyDict>> {
        let rust_input = validate_input(input)?;
        let bundle = verified_audit_bundle(&self.inner, rust_input, &decision.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        audit_bundle_to_dict(py, &bundle)
    }
}

pub(crate) fn validate_input(input: PyKernelInput) -> PyResult<KernelInput> {
    let rust_input = KernelInput::from(input);
    rust_input
        .validate()
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    Ok(rust_input)
}

fn decision_trace_to_dict<'py>(
    py: Python<'py>,
    trace: &calybris_core_rs::kernel::DecisionTrace,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("disabled", trace.rejections.disabled)?;
    d.set_item("quality", trace.rejections.quality)?;
    d.set_item("risk_ceiling", trace.rejections.risk_ceiling)?;
    d.set_item("latency", trace.rejections.latency)?;
    d.set_item("capability", trace.rejections.capability)?;
    d.set_item("provider", trace.rejections.provider)?;
    d.set_item("region", trace.rejections.region)?;
    d.set_item("budget", trace.rejections.budget)?;
    d.set_item("utility", trace.rejections.utility)?;
    d.set_item("evaluated_models", trace.evaluated_models)?;
    d.set_item("eligible_models", trace.eligible_models)?;
    Ok(d)
}

fn audit_bundle_to_dict<'py>(
    py: Python<'py>,
    bundle: &calybris_core_rs::verify::AuditBundle,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("schema_version", bundle.schema_version.clone())?;
    d.set_item("digest_algorithm", bundle.digest_algorithm.clone())?;
    d.set_item("proof_version", bundle.proof_version)?;
    d.set_item("policy_epoch", bundle.policy_epoch)?;
    d.set_item("catalog_epoch", bundle.catalog_epoch)?;
    d.set_item("created_by", bundle.created_by.clone())?;
    d.set_item("policy_digest_hex", bundle.policy_digest_hex.clone())?;
    d.set_item("input_digest_hex", bundle.input_digest_hex.clone())?;
    d.set_item("decision_digest_hex", bundle.decision_digest_hex.clone())?;
    d.set_item("replay_valid", bundle.replay_valid)?;
    Ok(d)
}

#[pyclass(name = "BudgetEngine", module = "calybris._core")]
struct PyBudgetEngine {
    pub(crate) inner: BudgetEngine,
}

#[pymethods]
impl PyBudgetEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: BudgetEngine::new(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "BudgetEngine(tenants={}, active_reservations={})",
            self.inner.tenant_count(),
            self.inner.active_reservations()
        )
    }

    fn ensure_tenant(&self, tenant_id: &str, budget_microcents: i64) {
        self.inner.ensure_tenant(tenant_id, budget_microcents);
    }

    fn set_max_reserved_microcents(&self, tenant_id: &str, max_microcents: i64) {
        self.inner
            .set_max_reserved_microcents(tenant_id, max_microcents);
    }

    fn top_up_tenant<'py>(
        &self,
        py: Python<'py>,
        tenant_id: &str,
        amount_microcents: i64,
    ) -> PyResult<Bound<'py, PyDict>> {
        top_up_to_dict(py, self.inner.top_up_tenant(tenant_id, amount_microcents))
    }

    fn try_reserve<'py>(
        &self,
        py: Python<'py>,
        tenant_id: &str,
        amount_microcents: i64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let (reservation, id) = self.inner.try_reserve(tenant_id, amount_microcents);
        reservation_to_dict(py, reservation, id)
    }

    fn commit<'py>(
        &self,
        py: Python<'py>,
        reservation_id: u64,
        actual_microcents: i64,
    ) -> PyResult<Bound<'py, PyDict>> {
        settlement_to_dict(py, self.inner.commit(reservation_id, actual_microcents))
    }

    fn release<'py>(&self, py: Python<'py>, reservation_id: u64) -> PyResult<Bound<'py, PyDict>> {
        settlement_to_dict(py, self.inner.release(reservation_id))
    }

    fn initial_microcents(&self, tenant_id: &str) -> Option<i64> {
        self.inner.initial_microcents(tenant_id)
    }

    fn remaining_microcents(&self, tenant_id: &str) -> Option<i64> {
        self.inner.remaining_microcents(tenant_id)
    }

    fn reserved_microcents(&self, tenant_id: &str) -> i64 {
        self.inner.reserved_microcents(tenant_id)
    }

    fn committed_microcents(&self, tenant_id: &str) -> Option<i64> {
        self.inner.committed_microcents(tenant_id)
    }

    fn tenant_count(&self) -> usize {
        self.inner.tenant_count()
    }

    fn active_reservations(&self) -> usize {
        self.inner.active_reservations()
    }

    fn verify_conservation<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        conservation_to_dict(py, self.inner.verify_conservation())
    }

    fn snapshot<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let snapshot = self.inner.snapshot();
        let d = PyDict::new(py);
        d.set_item("version", snapshot.version)?;
        d.set_item("active_reservations", snapshot.active_reservations)?;
        d.set_item("wal_high_watermark", snapshot.wal_high_watermark)?;
        let tenants = PyList::empty(py);
        for tenant in snapshot.tenants {
            let row = PyDict::new(py);
            row.set_item("tenant_id", tenant.tenant_id)?;
            row.set_item("initial_microcents", tenant.initial_microcents)?;
            row.set_item("remaining_microcents", tenant.remaining_microcents)?;
            row.set_item("reserved_microcents", tenant.reserved_microcents)?;
            row.set_item("committed_microcents", tenant.committed_microcents)?;
            tenants.append(row)?;
        }
        d.set_item("tenants", tenants)?;
        Ok(d)
    }

    fn prove_conservation<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        match prove_conservation(&self.inner) {
            Ok(proof) => {
                let d = PyDict::new(py);
                d.set_item("ledger_digest_hex", proof.ledger_digest_hex)?;
                d.set_item("snapshot_version", proof.snapshot_version)?;
                d.set_item("tenant_count", proof.tenant_count)?;
                d.set_item("active_reservations", proof.active_reservations)?;
                d.set_item("total_initial_microcents", proof.total_initial_microcents)?;
                d.set_item(
                    "total_committed_microcents",
                    proof.total_committed_microcents,
                )?;
                d.set_item(
                    "aggregate_totals_representable",
                    proof.aggregate_totals_representable,
                )?;
                Ok(d)
            }
            Err(status) => Err(pyo3::exceptions::PyValueError::new_err(status.to_string())),
        }
    }

    fn certify<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let cert = certify_ledger(&self.inner);
        let d = PyDict::new(py);
        d.set_item("snapshot_version", cert.snapshot_version)?;
        d.set_item("ledger_digest_hex", cert.ledger_digest_hex)?;
        d.set_item("tenant_count", cert.tenant_count)?;
        d.set_item("active_reservations", cert.active_reservations)?;
        d.set_item("conservation_balanced", cert.conservation_balanced)?;
        d.set_item("total_initial_microcents", cert.total_initial_microcents)?;
        d.set_item(
            "total_committed_microcents",
            cert.total_committed_microcents,
        )?;
        d.set_item(
            "aggregate_totals_representable",
            cert.aggregate_totals_representable,
        )?;
        d.set_item(
            "committed_since_last_certificate",
            cert.committed_since_last_certificate,
        )?;
        Ok(d)
    }
}

fn top_up_to_dict(py: Python<'_>, result: TopUpResult) -> PyResult<Bound<'_, PyDict>> {
    let d = PyDict::new(py);
    match result {
        TopUpResult::ToppedUp {
            added_microcents,
            new_initial_microcents,
            remaining_microcents,
        } => {
            d.set_item("status", "topped_up")?;
            d.set_item("added_microcents", added_microcents)?;
            d.set_item("new_initial_microcents", new_initial_microcents)?;
            d.set_item("remaining_microcents", remaining_microcents)?;
        }
        TopUpResult::MissingTenant => d.set_item("status", "missing_tenant")?,
        TopUpResult::InvalidAmount => d.set_item("status", "invalid_amount")?,
        TopUpResult::Overflow => d.set_item("status", "overflow")?,
    }
    Ok(d)
}

fn reservation_to_dict(
    py: Python<'_>,
    reservation: BudgetReservation,
    reservation_id: Option<u64>,
) -> PyResult<Bound<'_, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("reservation_id", reservation_id)?;
    match reservation {
        BudgetReservation::Reserved {
            remaining_microcents,
        } => {
            d.set_item("status", "reserved")?;
            d.set_item("remaining_microcents", remaining_microcents)?;
        }
        BudgetReservation::Insufficient {
            remaining_microcents,
            required_microcents,
        } => {
            d.set_item("status", "insufficient")?;
            d.set_item("remaining_microcents", remaining_microcents)?;
            d.set_item("required_microcents", required_microcents)?;
        }
        BudgetReservation::MissingTenant => d.set_item("status", "missing_tenant")?,
        BudgetReservation::MissingReservation => d.set_item("status", "missing_reservation")?,
        BudgetReservation::ExposureLimitExceeded {
            current_reserved_microcents,
            max_reserved_microcents,
        } => {
            d.set_item("status", "exposure_limit_exceeded")?;
            d.set_item("current_reserved_microcents", current_reserved_microcents)?;
            d.set_item("max_reserved_microcents", max_reserved_microcents)?;
        }
        BudgetReservation::Overflow {
            current_reserved_microcents,
        } => {
            d.set_item("status", "overflow")?;
            d.set_item("current_reserved_microcents", current_reserved_microcents)?;
        }
    }
    Ok(d)
}

fn settlement_to_dict(py: Python<'_>, settlement: BudgetSettlement) -> PyResult<Bound<'_, PyDict>> {
    let d = PyDict::new(py);
    match settlement {
        BudgetSettlement::Committed {
            remaining_microcents,
            actual_microcents,
        } => {
            d.set_item("status", "committed")?;
            d.set_item("remaining_microcents", remaining_microcents)?;
            d.set_item("actual_microcents", actual_microcents)?;
        }
        BudgetSettlement::Released {
            remaining_microcents,
            returned_microcents,
        } => {
            d.set_item("status", "released")?;
            d.set_item("remaining_microcents", remaining_microcents)?;
            d.set_item("returned_microcents", returned_microcents)?;
        }
        BudgetSettlement::Overrun {
            remaining_microcents,
        } => {
            d.set_item("status", "overrun")?;
            d.set_item("remaining_microcents", remaining_microcents)?;
        }
        BudgetSettlement::InvalidAmount => d.set_item("status", "invalid_amount")?,
        BudgetSettlement::MissingReservation => d.set_item("status", "missing_reservation")?,
        BudgetSettlement::MissingTenant => d.set_item("status", "missing_tenant")?,
        BudgetSettlement::Overflow {
            remaining_microcents,
        } => {
            d.set_item("status", "overflow")?;
            d.set_item("remaining_microcents", remaining_microcents)?;
        }
    }
    Ok(d)
}

fn conservation_to_dict(py: Python<'_>, status: ConservationStatus) -> PyResult<Bound<'_, PyDict>> {
    let d = PyDict::new(py);
    match status {
        ConservationStatus::Balanced => d.set_item("status", "balanced")?,
        ConservationStatus::Violation {
            tenant_id,
            delta_microcents,
        } => {
            d.set_item("status", "violation")?;
            d.set_item("tenant_id", tenant_id)?;
            d.set_item("delta_microcents", delta_microcents)?;
        }
        ConservationStatus::AggregateOverflow => d.set_item("status", "aggregate_overflow")?,
    }
    Ok(d)
}

#[pymodule]
#[pyo3(name = "_core")]
fn calybris_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyKernelModel>()?;
    m.add_class::<PyKernelInput>()?;
    m.add_class::<PyKernelDecision>()?;
    m.add_class::<PyPolicySnapshot>()?;
    m.add_class::<PyBudgetEngine>()?;
    production::register(m)?;

    // Mask helpers
    m.add("ALL_PROVIDERS", ALL_PROVIDERS)?;
    m.add("ALL_REGIONS", ALL_REGIONS)?;
    m.add("MICROCENTS_PER_CENT", MICROCENTS_PER_CENT)?;

    // Action codes — avoids magic numbers in Python callers
    m.add("ACTION_EXECUTE_REQUESTED", 1u8)?;
    m.add("ACTION_SUBSTITUTE", 2u8)?;
    m.add("ACTION_REJECT", 3u8)?;

    // Reason codes
    m.add("REASON_REQUESTED_MODEL_MAXIMIZES_UTILITY", 1u16)?;
    m.add("REASON_ALTERNATIVE_MAXIMIZES_UTILITY", 2u16)?;
    m.add("REASON_RISK_HARD_LIMIT", 100u16)?;
    m.add("REASON_CONFIDENCE_HARD_LIMIT", 101u16)?;
    m.add("REASON_NO_ENABLED_MODEL", 102u16)?;
    m.add("REASON_QUALITY_CONSTRAINT", 103u16)?;
    m.add("REASON_LATENCY_CONSTRAINT", 104u16)?;
    m.add("REASON_CAPABILITY_CONSTRAINT", 105u16)?;
    m.add("REASON_PROVIDER_CONSTRAINT", 106u16)?;
    m.add("REASON_REGION_CONSTRAINT", 107u16)?;
    m.add("REASON_BUDGET_CONSTRAINT", 108u16)?;
    m.add("REASON_NON_POSITIVE_UTILITY", 109u16)?;
    m.add("REASON_RISK_CEILING_CONSTRAINT", 110u16)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use calybris_core_rs::kernel::ALL_REGIONS;

    fn sample_snapshot() -> PyPolicySnapshot {
        PyPolicySnapshot {
            inner: PolicySnapshot::try_new(
                1,
                1,
                9_600,
                5_500,
                3_500,
                2,
                vec![
                    KernelModel {
                        model_id: 1,
                        provider_id: 0,
                        quality_bps: 9_000,
                        risk_ceiling_bps: 9_500,
                        enabled: 1,
                        p95_latency_ms: 200,
                        capabilities: 0,
                        region_mask: ALL_REGIONS,
                        input_cost_microunits_per_million_tokens: 250,
                        output_cost_microunits_per_million_tokens: 1_000,
                    },
                    KernelModel {
                        model_id: 2,
                        provider_id: 1,
                        quality_bps: 7_000,
                        risk_ceiling_bps: 9_500,
                        enabled: 1,
                        p95_latency_ms: 90,
                        capabilities: 0,
                        region_mask: ALL_REGIONS,
                        input_cost_microunits_per_million_tokens: 25,
                        output_cost_microunits_per_million_tokens: 125,
                    },
                ],
            )
            .expect("valid sample policy"),
        }
    }

    fn sample_input() -> PyKernelInput {
        PyKernelInput::new(
            1,
            1,
            1_000,
            500,
            100_000,
            50_000_000,
            1_000,
            9_000,
            5_000,
            1_000,
            0,
            ALL_PROVIDERS,
            0,
        )
        .expect("valid sample input")
    }

    #[test]
    fn prescribe_executes_requested_model() {
        let snap = sample_snapshot();
        let input = sample_input();
        let decision = snap.prescribe(input).expect("valid prescribe");
        assert_eq!(decision.action(), "execute_requested");
        assert_eq!(decision.selected_model_id(), 1);
        assert!(decision.is_requested_execution());
        assert!(!decision.is_substitution());
        assert!(decision.is_executable());
        assert!(!decision.is_rejected());
    }

    #[test]
    fn fingerprint_is_64_hex_chars() {
        assert_eq!(sample_snapshot().fingerprint().len(), 64);
    }

    #[test]
    fn invalid_policy_fails_validation() {
        let result = PolicySnapshot::try_new(
            1,
            1,
            10_001, // exceeds MAX_BPS = 10_000
            5_500,
            3_500,
            2,
            vec![KernelModel {
                model_id: 1,
                provider_id: 0,
                quality_bps: 9_000,
                risk_ceiling_bps: 9_500,
                enabled: 1,
                p95_latency_ms: 200,
                capabilities: 0,
                region_mask: ALL_REGIONS,
                input_cost_microunits_per_million_tokens: 250,
                output_cost_microunits_per_million_tokens: 1_000,
            }],
        );
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hard_risk_limit_bps"));
    }

    #[test]
    fn decision_equality_deterministic() {
        let snap = sample_snapshot();
        let input = sample_input();
        let a = snap.prescribe(input).expect("valid prescribe");
        let b = snap.prescribe(input).expect("valid prescribe");
        assert!(a.__eq__(&b));
    }

    #[test]
    fn decision_repr_contains_action_and_sequence() {
        let repr = sample_snapshot()
            .prescribe(sample_input())
            .expect("valid prescribe")
            .__repr__();
        assert!(repr.contains("execute_requested"));
        assert!(repr.contains("seq=1"));
    }

    #[test]
    fn policy_snapshot_exposes_all_parameter_getters() {
        let snap = sample_snapshot();
        assert_eq!(snap.hard_risk_limit_bps(), 9_600);
        assert_eq!(snap.minimum_confidence_bps(), 5_500);
        assert_eq!(snap.risk_penalty_multiplier_bps(), 3_500);
        assert_eq!(snap.latency_penalty_microunits_per_ms(), 2);
    }

    #[test]
    fn policy_snapshot_models_list_matches_construction() {
        let models = sample_snapshot().models();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].model_id, 1);
        assert_eq!(models[1].model_id, 2);
    }

    #[test]
    fn model_equality_compares_all_fields() {
        let base = KernelModel {
            model_id: 1,
            provider_id: 0,
            quality_bps: 9_000,
            risk_ceiling_bps: 9_500,
            enabled: 1,
            p95_latency_ms: 200,
            capabilities: 0,
            region_mask: ALL_REGIONS,
            input_cost_microunits_per_million_tokens: 250,
            output_cost_microunits_per_million_tokens: 1_000,
        };
        let m1 = PyKernelModel::from(&base);
        let m2 = m1.clone();
        assert!(m1.__eq__(&m2));
        let m3 = PyKernelModel::from(&KernelModel {
            model_id: 2,
            ..base
        });
        assert!(!m1.__eq__(&m3));
    }

    #[test]
    fn verify_status_valid_for_correct_decision() {
        let snap = sample_snapshot();
        let input = sample_input();
        let decision = snap.prescribe(input).expect("valid prescribe");
        assert_eq!(snap.verify_status(input, &decision).unwrap(), "valid");
    }
}
