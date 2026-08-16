// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Input-format adapters layered over the common redaction runtime.

pub mod argv {
    pub use crate::argv::ArgvItem;
    pub use crate::argv::ArgvRedactionSession;
    pub use crate::argv::ArgvRedactor;
    pub use crate::argv::RedactedArgv;
}

pub mod env {
    pub use crate::env::EnvRedactionSession;
    pub use crate::env::EnvRedactor;
    pub use crate::env::RedactedEnv;
    pub use crate::env::RedactedEnvPair;
}

#[cfg(feature = "http")]
pub mod http {
    pub use crate::http::BodyBudget;
    pub use crate::http::BodyBudgetBuilder;
    pub use crate::http::BodyBudgetError;
    pub use crate::http::BodyCapture;
    pub use crate::http::BodyCaptureError;
    pub use crate::http::BodyRedaction;
    pub use crate::http::BodyRedactionReason;
    pub use crate::http::BodyRedactionStatus;
    pub use crate::http::HttpPolicy;
    pub use crate::http::HttpRedactionSession;
    pub use crate::http::HttpRedactor;
    pub use crate::http::RedactedHeaders;
    pub use crate::http::TextBodyPolicy;
    pub use crate::http::UnkeyedJsonValuePolicy;
    pub use crate::http::UrlPathPolicy;
}

#[cfg(feature = "json")]
pub mod json {
    pub use crate::json::JsonRedactionOutput;
    pub use crate::json::JsonRedactionSession;
    pub use crate::json::RedactedJson;
    pub use crate::json::RedactedJsonText;
    pub use crate::json::redact_json_text_in_place;
}

#[cfg(feature = "uri")]
pub mod uri {
    pub use crate::uri::UriComponent;
    pub use crate::uri::UriFragmentPolicy;
    pub use crate::uri::UriInspection;
    pub use crate::uri::UriPathPolicy;
    pub use crate::uri::UriPolicy;
    pub use crate::uri::UriRedaction;
    pub use crate::uri::UriRedactionReason;
    pub use crate::uri::UriRedactionSession;
    pub use crate::uri::UriRedactionStatus;
    pub use crate::uri::UriRedactor;
}
