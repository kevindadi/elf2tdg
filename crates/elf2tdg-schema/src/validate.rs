//! Cross-reference and invariant validation for TDG documents.
//!
//! Validation is deliberately strict about references and numeric ranges, but
//! permissive about analyzer diagnostics: a TDG may contain warnings and still
//! be structurally valid.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::addr::Addr;
use crate::id::{
    BlockId, ContextId, EdgeId, FrequencyDomainId, FunctionId, ScopeId, TimingModelId,
};
use crate::model::{
    BasicBlock, Context, ContextKind, Edge, Function, JoinTarget, Scope, SpawnTarget, Tdg,
};
use crate::timing::FrequencyDomain;

/// Machine-readable validation issue code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationCode {
    /// The document uses a schema major version this crate does not support.
    UnsupportedSchemaVersion,
    /// A required string field is empty.
    EmptyField,
    /// An ID does not have the required prefix/suffix form.
    InvalidId,
    /// Two nodes share an ID.
    DuplicateId,
    /// An edge or context references a missing node.
    DanglingReference,
    /// A basic-block successor points into another function.
    InvalidBlockOwner,
    /// A function/block/instruction address range is inconsistent.
    InvalidRange,
    /// A call/spawn/join site lies outside its containing function.
    SiteOutOfRange,
    /// A cycle/time range is negative, non-finite, or inverted.
    InvalidCostRange,
    /// A frequency domain has a zero frequency.
    InvalidFrequency,
    /// A block references an unknown timing model.
    UnknownTimingModel,
    /// A context parent chain contains a cycle.
    ParentCycle,
    /// A scope member is not a spawn edge.
    InvalidScopeMember,
    /// A scope's exit precedes its entry.
    InvalidScopeRange,
    /// An ISR-activation edge points at a non-ISR context.
    ContextKindMismatch,
    /// A spawn edge's entry does not match the target context entry.
    SpawnEntryMismatch,
    /// A context's `spawn_edge` is not a spawn edge creating that context.
    InvalidSpawnEdge,
}

/// One validation problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationIssue {
    /// Machine-readable issue code.
    pub code: ValidationCode,
    /// JSON-pointer-like location inside the document.
    pub path: String,
    /// Human-readable explanation.
    pub message: String,
}

/// Error returned by [`Tdg::ensure_valid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// All issues found.
    pub issues: Vec<ValidationIssue>,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TDG validation failed with {} issue(s)",
            self.issues.len()
        )
    }
}

impl std::error::Error for ValidationError {}

impl Tdg {
    /// Validates the document and returns every issue found.
    ///
    /// An empty vector means the document satisfies the schema invariants.
    #[must_use]
    pub fn validate(&self) -> Vec<ValidationIssue> {
        self.validate_with_limit(usize::MAX)
    }

    /// Validates the document, collecting at most `limit` issues.
    ///
    /// The limit prevents a hostile document from producing unbounded
    /// diagnostics.
    #[must_use]
    pub fn validate_with_limit(&self, limit: usize) -> Vec<ValidationIssue> {
        let mut validator = Validator {
            tdg: self,
            issues: Vec::new(),
            limit,
        };
        validator.run();
        validator.issues
    }

    /// Validates the document and converts issues into an error.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when any issue is found.
    pub fn ensure_valid(&self) -> Result<(), ValidationError> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(())
        } else {
            Err(ValidationError { issues })
        }
    }
}

struct Validator<'a> {
    tdg: &'a Tdg,
    issues: Vec<ValidationIssue>,
    limit: usize,
}

impl Validator<'_> {
    fn push_issue(
        &mut self,
        code: ValidationCode,
        path: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.issues.len() < self.limit {
            self.issues.push(ValidationIssue {
                code,
                path: path.into(),
                message: message.into(),
            });
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run(&mut self) {
        let tdg = self.tdg;

        if !schema_version_supported(&tdg.schema_version) {
            self.push_issue(
                ValidationCode::UnsupportedSchemaVersion,
                "/schema_version",
                format!(
                    "unsupported schema version {:?}; this crate supports 1.x",
                    tdg.schema_version
                ),
            );
        }
        for (field, value) in [
            ("name", tdg.tool.name.as_str()),
            ("version", tdg.tool.version.as_str()),
            ("rules_version", tdg.tool.rules_version.as_str()),
            (
                "timing_tables_version",
                tdg.tool.timing_tables_version.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("/tool/{field}"),
                    format!("tool.{field} must not be empty"),
                );
            }
        }
        if tdg.image.arch.trim().is_empty() {
            self.push_issue(
                ValidationCode::EmptyField,
                "/image/arch",
                "image.arch must not be empty",
            );
        }

        // ---- timing metadata -------------------------------------------------
        let mut model_ids: BTreeSet<TimingModelId> = BTreeSet::new();
        for (index, model) in tdg.timing.models.iter().enumerate() {
            let path = format!("/timing/models/{index}");
            if !model.id.is_well_formed() {
                self.push_issue(
                    ValidationCode::InvalidId,
                    format!("{path}/id"),
                    format!("invalid timing model ID {:?}", model.id),
                );
            }
            if model.arch.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("{path}/arch"),
                    "timing model arch must not be empty",
                );
            }
            if model.table_version.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("{path}/table_version"),
                    "timing model table_version must not be empty",
                );
            }
            if !model_ids.insert(model.id.clone()) {
                self.push_issue(
                    ValidationCode::DuplicateId,
                    format!("{path}/id"),
                    format!("duplicate timing model ID {}", model.id),
                );
            }
        }

        let mut domains: BTreeMap<FrequencyDomainId, &FrequencyDomain> = BTreeMap::new();
        for (index, domain) in tdg.timing.frequency_domains.iter().enumerate() {
            let path = format!("/timing/frequency_domains/{index}");
            if !domain.id.is_well_formed() {
                self.push_issue(
                    ValidationCode::InvalidId,
                    format!("{path}/id"),
                    format!("invalid frequency domain ID {:?}", domain.id),
                );
            }
            if domain.name.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("{path}/name"),
                    "frequency domain name must not be empty",
                );
            }
            if domain.hz == 0 {
                self.push_issue(
                    ValidationCode::InvalidFrequency,
                    format!("{path}/hz"),
                    "frequency must be greater than zero",
                );
            }
            if domains.insert(domain.id.clone(), domain).is_some() {
                self.push_issue(
                    ValidationCode::DuplicateId,
                    format!("{path}/id"),
                    format!("duplicate frequency domain ID {}", domain.id),
                );
            }
        }
        if let Some(default) = &tdg.timing.default_frequency_domain {
            if !default.is_well_formed() {
                self.push_issue(
                    ValidationCode::InvalidId,
                    "/timing/default_frequency_domain",
                    format!("invalid frequency domain ID {default:?}"),
                );
            }
            if !domains.contains_key(default) {
                self.push_issue(
                    ValidationCode::DanglingReference,
                    "/timing/default_frequency_domain",
                    format!("unknown frequency domain {default}"),
                );
            }
        }

        // ---- functions and blocks -------------------------------------------
        let mut functions: BTreeMap<FunctionId, &Function> = BTreeMap::new();
        let mut blocks: BTreeMap<BlockId, (FunctionId, &BasicBlock)> = BTreeMap::new();

        for (function_index, function) in tdg.functions.iter().enumerate() {
            let function_path = format!("/functions/{function_index}");
            if !function.id.is_well_formed() {
                self.push_issue(
                    ValidationCode::InvalidId,
                    format!("{function_path}/id"),
                    format!("invalid function ID {:?}", function.id),
                );
            }
            if function.primary_name.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("{function_path}/primary_name"),
                    "function primary_name must not be empty",
                );
            }
            if function.size > 0 && function.end().is_none() {
                self.push_issue(
                    ValidationCode::InvalidRange,
                    function_path.clone(),
                    format!(
                        "function range {} + {} overflows the address space",
                        function.address, function.size
                    ),
                );
            }
            if let Some(timing) = &function.timing
                && !timing.static_block_sum_cycles.is_valid()
            {
                self.push_issue(
                    ValidationCode::InvalidCostRange,
                    format!("{function_path}/timing/static_block_sum_cycles"),
                    "invalid static block-sum cycle range",
                );
            }
            if functions.insert(function.id.clone(), function).is_some() {
                self.push_issue(
                    ValidationCode::DuplicateId,
                    format!("{function_path}/id"),
                    format!("duplicate function ID {}", function.id),
                );
            }

            for (block_index, block) in function.blocks.iter().enumerate() {
                let block_path = format!("{function_path}/blocks/{block_index}");
                if !block.id.is_well_formed() {
                    self.push_issue(
                        ValidationCode::InvalidId,
                        format!("{block_path}/id"),
                        format!("invalid block ID {:?}", block.id),
                    );
                }
                if block.size > 0 && block.end().is_none() {
                    self.push_issue(
                        ValidationCode::InvalidRange,
                        block_path.clone(),
                        format!(
                            "block range {} + {} overflows the address space",
                            block.address, block.size
                        ),
                    );
                }
                if let (Some(function_end), Some(block_end)) = (function.end(), block.end())
                    && (block.address < function.address || block_end > function_end)
                {
                    self.push_issue(
                        ValidationCode::InvalidRange,
                        format!("{block_path}/address"),
                        format!(
                            "block [{}..{}) is outside function [{}..{})",
                            block.address, block_end, function.address, function_end
                        ),
                    );
                }
                if blocks
                    .insert(block.id.clone(), (function.id.clone(), block))
                    .is_some()
                {
                    self.push_issue(
                        ValidationCode::DuplicateId,
                        format!("{block_path}/id"),
                        format!("duplicate block ID {}", block.id),
                    );
                }
                self.check_block_timing(block, &block_path, &model_ids, &domains);
                self.check_instructions(block, &block_path);
            }
        }

        self.check_block_successors(&blocks);

        // ---- contexts --------------------------------------------------------
        let mut contexts: BTreeMap<ContextId, &Context> = BTreeMap::new();
        for (index, context) in tdg.contexts.iter().enumerate() {
            let path = format!("/contexts/{index}");
            if !context.id.is_well_formed() {
                self.push_issue(
                    ValidationCode::InvalidId,
                    format!("{path}/id"),
                    format!("invalid context ID {:?}", context.id),
                );
            }
            if context.name.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("{path}/name"),
                    "context name must not be empty",
                );
            }
            if contexts.insert(context.id.clone(), context).is_some() {
                self.push_issue(
                    ValidationCode::DuplicateId,
                    format!("{path}/id"),
                    format!("duplicate context ID {}", context.id),
                );
            }
        }

        // ---- scopes ----------------------------------------------------------
        let mut scopes: BTreeMap<ScopeId, &Scope> = BTreeMap::new();
        for (index, scope) in tdg.scopes.iter().enumerate() {
            let path = format!("/scopes/{index}");
            if !scope.id.is_well_formed() {
                self.push_issue(
                    ValidationCode::InvalidId,
                    format!("{path}/id"),
                    format!("invalid scope ID {:?}", scope.id),
                );
            }
            if scopes.insert(scope.id.clone(), scope).is_some() {
                self.push_issue(
                    ValidationCode::DuplicateId,
                    format!("{path}/id"),
                    format!("duplicate scope ID {}", scope.id),
                );
            }
            if !contexts.contains_key(&scope.entering_context) {
                self.push_issue(
                    ValidationCode::DanglingReference,
                    format!("{path}/entering_context"),
                    format!("unknown context {}", scope.entering_context),
                );
            }
            if let Some(exit) = scope.exit_site
                && exit < scope.enter_site
            {
                self.push_issue(
                    ValidationCode::InvalidScopeRange,
                    format!("{path}/exit_site"),
                    "scope exit precedes scope entry",
                );
            }
        }

        // ---- edges -----------------------------------------------------------
        let mut edges: BTreeMap<EdgeId, &Edge> = BTreeMap::new();
        for (index, edge) in tdg.edges.iter().enumerate() {
            let path = format!("/edges/{index}");
            if !edge.id().is_well_formed() {
                self.push_issue(
                    ValidationCode::InvalidId,
                    format!("{path}/id"),
                    format!("invalid edge ID {:?}", edge.id()),
                );
            }
            if edges.insert(edge.id().clone(), edge).is_some() {
                self.push_issue(
                    ValidationCode::DuplicateId,
                    format!("{path}/id"),
                    format!("duplicate edge ID {}", edge.id()),
                );
            }
        }

        self.check_context_references(&functions, &contexts, &edges, &domains);
        self.check_edge_references(&functions, &contexts, &scopes, &edges);
        self.check_scope_members(&edges, &scopes);
        self.check_parent_cycles(&contexts);
        self.check_diagnostics(&functions, &contexts);
    }

    fn check_block_timing(
        &mut self,
        block: &BasicBlock,
        block_path: &str,
        model_ids: &BTreeSet<TimingModelId>,
        domains: &BTreeMap<FrequencyDomainId, &FrequencyDomain>,
    ) {
        let Some(timing) = &block.timing else {
            return;
        };
        if !timing.cycles.is_valid() {
            self.push_issue(
                ValidationCode::InvalidCostRange,
                format!("{block_path}/timing/cycles"),
                "invalid cycle range",
            );
        }
        if let Some(time_ns) = timing.time_ns
            && !time_ns.is_valid()
        {
            self.push_issue(
                ValidationCode::InvalidCostRange,
                format!("{block_path}/timing/time_ns"),
                "invalid time range",
            );
        }
        if let Some(model) = &timing.model
            && !model_ids.contains(model)
        {
            self.push_issue(
                ValidationCode::UnknownTimingModel,
                format!("{block_path}/timing/model"),
                format!("unknown timing model {model}"),
            );
        }
        if let Some(domain) = &timing.frequency_domain
            && !domains.contains_key(domain)
        {
            self.push_issue(
                ValidationCode::DanglingReference,
                format!("{block_path}/timing/frequency_domain"),
                format!("unknown frequency domain {domain}"),
            );
        }
    }

    fn check_instructions(&mut self, block: &BasicBlock, block_path: &str) {
        let block_end = block.end().filter(|_| block.size > 0);
        for (index, instruction) in block.instructions.iter().enumerate() {
            let path = format!("{block_path}/instructions/{index}");
            if instruction.size == 0 {
                self.push_issue(
                    ValidationCode::InvalidRange,
                    format!("{path}/size"),
                    "instruction size must be greater than zero",
                );
            }
            if let Some(block_end) = block_end {
                match instruction.end() {
                    None => self.push_issue(
                        ValidationCode::InvalidRange,
                        format!("{path}/address"),
                        "instruction range overflows the address space",
                    ),
                    Some(end) if instruction.address < block.address || end > block_end => {
                        self.push_issue(
                            ValidationCode::InvalidRange,
                            format!("{path}/address"),
                            format!(
                                "instruction [{}..{}) is outside block [{}..{})",
                                instruction.address, end, block.address, block_end
                            ),
                        );
                    }
                    Some(_) => {}
                }
            }
            if !instruction.cycles.is_valid() {
                self.push_issue(
                    ValidationCode::InvalidCostRange,
                    format!("{path}/cycles"),
                    "invalid instruction cycle range",
                );
            }
        }
    }

    fn check_block_successors(&mut self, blocks: &BTreeMap<BlockId, (FunctionId, &BasicBlock)>) {
        let tdg = self.tdg;
        for (function_index, function) in tdg.functions.iter().enumerate() {
            for (block_index, block) in function.blocks.iter().enumerate() {
                for (successor_index, successor) in block.successors.iter().enumerate() {
                    let path = format!(
                        "/functions/{function_index}/blocks/{block_index}/successors/{successor_index}"
                    );
                    match blocks.get(successor) {
                        None => self.push_issue(
                            ValidationCode::DanglingReference,
                            &path,
                            format!("unknown block {successor}"),
                        ),
                        Some((owner, _)) if owner != &function.id => self.push_issue(
                            ValidationCode::InvalidBlockOwner,
                            &path,
                            format!(
                                "block {successor} belongs to {}, not {}",
                                owner, function.id
                            ),
                        ),
                        Some(_) => {}
                    }
                }
            }
        }
    }

    fn check_context_references(
        &mut self,
        functions: &BTreeMap<FunctionId, &Function>,
        contexts: &BTreeMap<ContextId, &Context>,
        edges: &BTreeMap<EdgeId, &Edge>,
        domains: &BTreeMap<FrequencyDomainId, &FrequencyDomain>,
    ) {
        let tdg = self.tdg;
        for (index, context) in tdg.contexts.iter().enumerate() {
            let path = format!("/contexts/{index}");
            if !functions.contains_key(&context.entry) {
                self.push_issue(
                    ValidationCode::DanglingReference,
                    format!("{path}/entry"),
                    format!("unknown entry function {}", context.entry),
                );
            }
            if let Some(parent) = &context.parent
                && !contexts.contains_key(parent)
            {
                self.push_issue(
                    ValidationCode::DanglingReference,
                    format!("{path}/parent"),
                    format!("unknown parent context {parent}"),
                );
            }
            if let Some(domain) = &context.frequency_domain
                && !domains.contains_key(domain)
            {
                self.push_issue(
                    ValidationCode::DanglingReference,
                    format!("{path}/frequency_domain"),
                    format!("unknown frequency domain {domain}"),
                );
            }
            if let Some(spawn_edge) = &context.spawn_edge {
                match edges.get(spawn_edge) {
                    None => self.push_issue(
                        ValidationCode::DanglingReference,
                        format!("{path}/spawn_edge"),
                        format!("unknown edge {spawn_edge}"),
                    ),
                    Some(Edge::Spawn {
                        target:
                            SpawnTarget::Context {
                                context: target_context,
                                ..
                            },
                        ..
                    }) if target_context == &context.id => {}
                    Some(_) => self.push_issue(
                        ValidationCode::InvalidSpawnEdge,
                        format!("{path}/spawn_edge"),
                        format!(
                            "edge {spawn_edge} is not a spawn edge creating context {}",
                            context.id
                        ),
                    ),
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn check_edge_references(
        &mut self,
        functions: &BTreeMap<FunctionId, &Function>,
        contexts: &BTreeMap<ContextId, &Context>,
        scopes: &BTreeMap<ScopeId, &Scope>,
        edges: &BTreeMap<EdgeId, &Edge>,
    ) {
        let tdg = self.tdg;
        for (index, edge) in tdg.edges.iter().enumerate() {
            let path = format!("/edges/{index}");
            match edge {
                Edge::Call {
                    caller,
                    callee,
                    site,
                    ..
                } => {
                    self.check_function_ref(functions, caller, &format!("{path}/caller"));
                    self.check_function_ref(functions, callee, &format!("{path}/callee"));
                    self.check_site(functions, caller, *site, &format!("{path}/site"));
                }
                Edge::Spawn {
                    from_function,
                    target,
                    site,
                    name,
                    ..
                } => {
                    if name.as_deref().is_some_and(|name| name.trim().is_empty()) {
                        self.push_issue(
                            ValidationCode::EmptyField,
                            format!("{path}/name"),
                            "spawn name must not be empty when present",
                        );
                    }
                    self.check_function_ref(
                        functions,
                        from_function,
                        &format!("{path}/from_function"),
                    );
                    match target {
                        SpawnTarget::Context { context, entry } => {
                            self.check_function_ref(
                                functions,
                                entry,
                                &format!("{path}/target/entry"),
                            );
                            match contexts.get(context) {
                                None => self.push_issue(
                                    ValidationCode::DanglingReference,
                                    format!("{path}/target/context"),
                                    format!("unknown context {context}"),
                                ),
                                Some(target_context) if &target_context.entry != entry => {
                                    self.push_issue(
                                        ValidationCode::SpawnEntryMismatch,
                                        format!("{path}/target/entry"),
                                        format!(
                                            "spawn entry {entry} does not match context entry {}",
                                            target_context.entry
                                        ),
                                    );
                                }
                                Some(_) => {}
                            }
                        }
                        SpawnTarget::Opaque { candidates } => {
                            for (candidate_index, function) in candidates.iter().enumerate() {
                                self.check_function_ref(
                                    functions,
                                    function,
                                    &format!("{path}/target/candidates/{candidate_index}"),
                                );
                            }
                        }
                    }
                    self.check_site(functions, from_function, *site, &format!("{path}/site"));
                }
                Edge::Join {
                    from_function,
                    from_context,
                    target,
                    site,
                    scope,
                    ..
                } => {
                    self.check_function_ref(
                        functions,
                        from_function,
                        &format!("{path}/from_function"),
                    );
                    match target {
                        JoinTarget::Context { context } => self.check_context_ref(
                            contexts,
                            context,
                            &format!("{path}/target/context"),
                        ),
                        JoinTarget::Opaque { candidates } => {
                            for (candidate_index, context) in candidates.iter().enumerate() {
                                self.check_context_ref(
                                    contexts,
                                    context,
                                    &format!("{path}/target/candidates/{candidate_index}"),
                                );
                            }
                        }
                    }
                    if let Some(from_context) = from_context {
                        self.check_context_ref(
                            contexts,
                            from_context,
                            &format!("{path}/from_context"),
                        );
                    }
                    if let Some(scope) = scope
                        && !scopes.contains_key(scope)
                    {
                        self.push_issue(
                            ValidationCode::DanglingReference,
                            format!("{path}/scope"),
                            format!("unknown scope {scope}"),
                        );
                    }
                    self.check_site(functions, from_function, *site, &format!("{path}/site"));
                }
                Edge::Await {
                    from_context,
                    target,
                    ..
                } => {
                    self.check_context_ref(contexts, from_context, &format!("{path}/from_context"));
                    match target {
                        crate::model::AwaitTarget::Context { context } => {
                            self.check_context_ref(
                                contexts,
                                context,
                                &format!("{path}/target/context"),
                            );
                        }
                        crate::model::AwaitTarget::Function { function } => {
                            self.check_function_ref(
                                functions,
                                function,
                                &format!("{path}/target/function"),
                            );
                        }
                        crate::model::AwaitTarget::Opaque { candidates } => {
                            for (candidate_index, function) in candidates.iter().enumerate() {
                                self.check_function_ref(
                                    functions,
                                    function,
                                    &format!("{path}/target/candidates/{candidate_index}"),
                                );
                            }
                        }
                    }
                }
                Edge::CallbackBind {
                    from_function,
                    callback,
                    target_context,
                    site,
                    ..
                } => {
                    self.check_function_ref(
                        functions,
                        from_function,
                        &format!("{path}/from_function"),
                    );
                    self.check_function_ref(functions, callback, &format!("{path}/callback"));
                    if let Some(target_context) = target_context {
                        self.check_context_ref(
                            contexts,
                            target_context,
                            &format!("{path}/target_context"),
                        );
                    }
                    self.check_site(functions, from_function, *site, &format!("{path}/site"));
                }
                Edge::IsrActivate { to_context, .. } => match contexts.get(to_context) {
                    None => self.push_issue(
                        ValidationCode::DanglingReference,
                        format!("{path}/to_context"),
                        format!("unknown context {to_context}"),
                    ),
                    Some(context) if context.kind != ContextKind::Isr => self.push_issue(
                        ValidationCode::ContextKindMismatch,
                        format!("{path}/to_context"),
                        format!(
                            "ISR activation targets {} context {}",
                            context_kind_name(context.kind),
                            context.id
                        ),
                    ),
                    Some(_) => {}
                },
                Edge::Preempts {
                    from_context,
                    to_context,
                    ..
                } => {
                    self.check_context_ref(contexts, from_context, &format!("{path}/from_context"));
                    self.check_context_ref(contexts, to_context, &format!("{path}/to_context"));
                }
            }
            // Keep the borrow of `edges` meaningful for future edge variants:
            // every edge in the document must be reachable from the map.
            debug_assert!(edges.contains_key(edge.id()));
        }
    }

    fn check_scope_members(
        &mut self,
        edges: &BTreeMap<EdgeId, &Edge>,
        scopes: &BTreeMap<ScopeId, &Scope>,
    ) {
        let tdg = self.tdg;
        for (scope_index, scope) in tdg.scopes.iter().enumerate() {
            debug_assert!(scopes.contains_key(&scope.id));
            for (member_index, member) in scope.members.iter().enumerate() {
                let path = format!("/scopes/{scope_index}/members/{member_index}");
                match edges.get(member) {
                    None => self.push_issue(
                        ValidationCode::DanglingReference,
                        &path,
                        format!("unknown edge {member}"),
                    ),
                    Some(Edge::Spawn { .. }) => {}
                    Some(_) => self.push_issue(
                        ValidationCode::InvalidScopeMember,
                        &path,
                        format!("edge {member} is not a spawn edge"),
                    ),
                }
            }
        }
    }

    fn check_parent_cycles(&mut self, contexts: &BTreeMap<ContextId, &Context>) {
        let tdg = self.tdg;
        let mut done: BTreeSet<ContextId> = BTreeSet::new();
        for (index, context) in tdg.contexts.iter().enumerate() {
            if done.contains(&context.id) {
                continue;
            }
            let mut path: Vec<ContextId> = Vec::new();
            let mut in_path: BTreeSet<ContextId> = BTreeSet::new();
            let mut current = Some(context.id.clone());
            while let Some(id) = current {
                if done.contains(&id) {
                    break;
                }
                if !in_path.insert(id.clone()) {
                    self.push_issue(
                        ValidationCode::ParentCycle,
                        format!("/contexts/{index}/parent"),
                        format!("parent chain starting at {} contains a cycle", context.id),
                    );
                    break;
                }
                path.push(id.clone());
                current = contexts.get(&id).and_then(|node| node.parent.clone());
            }
            for id in path {
                done.insert(id);
            }
        }
    }

    fn check_diagnostics(
        &mut self,
        functions: &BTreeMap<FunctionId, &Function>,
        contexts: &BTreeMap<ContextId, &Context>,
    ) {
        let tdg = self.tdg;
        for (index, diagnostic) in tdg.diagnostics.iter().enumerate() {
            let path = format!("/diagnostics/{index}");
            if diagnostic.code.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("{path}/code"),
                    "diagnostic code must not be empty",
                );
            }
            if diagnostic.message.trim().is_empty() {
                self.push_issue(
                    ValidationCode::EmptyField,
                    format!("{path}/message"),
                    "diagnostic message must not be empty",
                );
            }
            if let Some(function) = &diagnostic.function {
                self.check_function_ref(functions, function, &format!("{path}/function"));
            }
            if let Some(context) = &diagnostic.context {
                self.check_context_ref(contexts, context, &format!("{path}/context"));
            }
        }
    }

    fn check_function_ref(
        &mut self,
        functions: &BTreeMap<FunctionId, &Function>,
        id: &FunctionId,
        path: &str,
    ) {
        if !functions.contains_key(id) {
            self.push_issue(
                ValidationCode::DanglingReference,
                path,
                format!("unknown function {id}"),
            );
        }
    }

    fn check_context_ref(
        &mut self,
        contexts: &BTreeMap<ContextId, &Context>,
        id: &ContextId,
        path: &str,
    ) {
        if !contexts.contains_key(id) {
            self.push_issue(
                ValidationCode::DanglingReference,
                path,
                format!("unknown context {id}"),
            );
        }
    }

    fn check_site(
        &mut self,
        functions: &BTreeMap<FunctionId, &Function>,
        function_id: &FunctionId,
        site: Addr,
        path: &str,
    ) {
        let Some(function) = functions.get(function_id) else {
            return;
        };
        if function.size == 0 {
            return;
        }
        let Some(end) = function.end() else {
            return;
        };
        if site < function.address || site >= end {
            self.push_issue(
                ValidationCode::SiteOutOfRange,
                path,
                format!(
                    "site {site} is outside function {} [{}..{})",
                    function.id, function.address, end
                ),
            );
        }
    }
}

fn context_kind_name(kind: ContextKind) -> &'static str {
    match kind {
        ContextKind::Startup => "startup",
        ContextKind::Main => "main",
        ContextKind::Thread => "thread",
        ContextKind::ScopedThread => "scoped-thread",
        ContextKind::AsyncTask => "async-task",
        ContextKind::Executor => "executor",
        ContextKind::Isr => "isr",
        ContextKind::TimerCallback => "timer-callback",
        ContextKind::SystemWorkqueue => "system-workqueue",
        ContextKind::KernelThread => "kernel-thread",
        ContextKind::Unknown => "unknown",
    }
}

fn schema_version_supported(version: &str) -> bool {
    match version.split_once('.') {
        Some((major, minor)) => major == "1" && !minor.is_empty(),
        None => false,
    }
}
