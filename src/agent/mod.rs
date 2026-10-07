//! The agent: one LLM-driven loop per session.
//!
//! The model owns the investigation (planning, methodology, what is still
//! unknown); the runtime owns the trusted boundary (scope, risk, argv,
//! execution, retries, context budgeting, persistence). Scan-specific
//! knowledge lives in tool parsers, never here.

pub mod context;
pub mod events;
pub mod executor;
pub mod file_tools;
pub mod http_provider;
pub mod model;
pub mod parsers;
pub mod policy;
pub mod provider;
pub mod research;
pub mod runtime;
pub mod vault;
pub mod web_search;

pub use context::{ActionRecord, BudgetReport, ContextManager, Finding, Observation, TokenBudget};
pub use events::AgentEvent;
pub use executor::{
    LocalProcessExecutor, ProcessExecutor, ProcessOutput, StubExecutor, ToolResult,
};
pub use http_provider::HttpRequestProvider;
pub use research::{RESEARCH_CAPABILITIES, ResearchProvider};

pub use model::{
    CliProvider, ContextView, Decision, ModelError, ModelProvider, OpenAiCompatibleProvider,
    OptionSet, OptionValue, StubProvider,
};
pub use parsers::{parse_tool_output, ParsedObservation};
pub use policy::{ExecutionPolicy, PolicyError, ScopePolicy};
pub use provider::{
    CapabilityProvider, CapabilityRequest, ExecutionContext, ProcessProvider, ProviderError,
    ProviderRegistry,
};
pub use runtime::{
    AgentRuntime, AgentSession, DriveOutcome, FinishReason, InvestigationResult, PlannedAction,
    RuntimeHandle, Target,
};
pub use vault::{VaultEntry, VaultManager};
