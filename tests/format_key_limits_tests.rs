use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use std::cell::Cell;
use std::ffi::OsStr;

fn policy_with_key_limit(maximum: usize) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_key_bytes(maximum);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy")
}

#[test]
fn test_env_key_limit_rejects_before_publication() {
    let redactor = Redactor::new(policy_with_key_limit(1));
    let output = redactor.redact_env("MODE", "rejected-value-427");
    assert!(!output.text().as_str().contains("rejected-value-427"));
    assert!(output.complete_text().is_err());
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    let error = redactor
        .inspect_env("MODE", "rejected-value-427")
        .expect_err("oversized classification key must make inspection inconclusive");
    assert!(
        error
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

#[test]
fn test_env_composer_key_limit_rejects_before_publication() {
    let redactor = Redactor::new(policy_with_key_limit(1));
    let output = redactor
        .text_composer()
        .env(|env| {
            env.pair("TOO_LONG", "rejected-value-427");
        })
        .finish();
    assert!(!output.text().as_str().contains("rejected-value-427"));
    assert!(output.complete_text().is_err());
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

#[test]
fn test_env_key_limit_byte_boundaries_and_disabled_policy() {
    let exact = Redactor::new(policy_with_key_limit(1));
    assert!(exact.redact_env("A", "value").complete_text().is_ok());
    assert!(exact.redact_env("", "value").complete_text().is_ok());
    for name in ["AB", "é"] {
        let output = exact.redact_env(name, "rejected-value-427");
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(output.complete_text().is_err());
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    let mut disabled_policy = policy_with_key_limit(1);
    let _ = disabled_policy.set_disabled(true);
    let disabled = Redactor::new(disabled_policy);
    let output = disabled.redact_env("AB", "rejected-value-427");
    assert!(!output.text().as_str().contains("rejected-value-427"));
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

#[test]
fn test_env_batch_key_limit_stops_before_reading_the_tail() {
    let redactor = Redactor::new(policy_with_key_limit(1));
    let pairs = [
        (OsStr::new("A"), OsStr::new("first")),
        (OsStr::new("TOO_LONG"), OsStr::new("rejected-value-427")),
        (OsStr::new("TAIL"), OsStr::new("tail-secret")),
    ];
    let reads = Cell::new(0);
    let mut index = 0;
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_env_pairs(std::iter::from_fn(|| {
        let pair = pairs.get(index).copied()?;
        index += 1;
        reads.set(reads.get() + 1);
        Some(pair)
    }));
    let output = batch.finish_with_marker("<redaction incomplete>");
    assert_eq!(reads.get(), 2);
    assert_eq!(output.text(handle).as_str(), "<redaction incomplete>");
    assert!(!output.text(handle).as_str().contains("rejected-value-427"));
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

#[test]
fn test_process_batch_environment_key_limit_stops_before_reading_the_tail() {
    let redactor = Redactor::new(policy_with_key_limit(1));
    let pairs = [
        (OsStr::new("A"), OsStr::new("first")),
        (OsStr::new("TOO_LONG"), OsStr::new("rejected-value-427")),
        (OsStr::new("TAIL"), OsStr::new("tail-secret")),
    ];
    let reads = Cell::new(0);
    let mut index = 0;
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_process(
        OsStr::new("tool"),
        std::iter::empty(),
        std::iter::from_fn(|| {
            let pair = pairs.get(index).copied()?;
            index += 1;
            reads.set(reads.get() + 1);
            Some(pair)
        }),
    );
    let output = batch.finish_with_marker("<redaction incomplete>");
    assert_eq!(reads.get(), 2);
    assert_eq!(output.text(handle).as_str(), "<redaction incomplete>");
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

#[cfg(feature = "uri")]
mod uri {
    use super::policy_with_key_limit;
    use qubit_redact::RedactionReason;
    use qubit_redact::Redactor;

    #[test]
    fn test_uri_query_key_limit_rejects_before_publication() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        let input = "https://example.test/?abcd=rejected-value-427";
        let output = redactor.redact_uri(input);
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(output.complete_text().is_err());
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        let error = redactor
            .inspect_uri(input)
            .expect_err("oversized key must make inspection inconclusive");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_uri_decoded_key_bytes_define_the_limit() {
        let exact = Redactor::new(policy_with_key_limit(1));
        assert!(
            exact
                .redact_uri("https://example.test/?%61=value")
                .complete_text()
                .is_ok()
        );
        let over = exact.redact_uri("https://example.test/?%61b=rejected-value-427");
        assert!(!over.text().as_str().contains("rejected-value-427"));
        assert!(
            over.summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }
}

#[cfg(feature = "http")]
mod http {
    use super::policy_with_key_limit;
    use http::HeaderMap;
    use http::HeaderValue;
    use qubit_redact::RedactionReason;
    use qubit_redact::Redactor;
    use qubit_redact::formats::http::BodyCapture;

    fn assert_rejected(output: qubit_redact::RedactionTextOutput) {
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(output.complete_text().is_err());
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_http_url_key_limit_rejects_before_publication() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        assert_rejected(redactor.redact_http_url("https://example.test/?abcd=rejected-value-427"));
        let error = redactor
            .inspect_http_url("https://example.test/?abcd=rejected-value-427")
            .expect_err("oversized key must make inspection inconclusive");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_http_header_key_limit_rejects_before_publication() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        let mut headers = HeaderMap::new();
        headers.insert("abcd", HeaderValue::from_static("rejected-value-427"));
        assert_rejected(redactor.redact_http_headers(&headers));
        let error = redactor
            .inspect_http_headers(&headers)
            .expect_err("oversized header name must make inspection inconclusive");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_http_form_key_limit_rejects_before_publication() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        let capture = BodyCapture::complete(b"abcd=rejected-value-427");
        assert_rejected(redactor.redact_http_body_with_content_type_text(
            capture,
            Some("application/x-www-form-urlencoded"),
        ));
        let error = redactor
            .inspect_http_body_with_content_type_text(
                capture,
                Some("application/x-www-form-urlencoded"),
            )
            .expect_err("oversized form key must make inspection inconclusive");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_http_form_plus_decoding_defines_key_length() {
        let redactor = Redactor::new(policy_with_key_limit(2));
        let capture = BodyCapture::complete(b"a+b=rejected-value-427");
        let output = redactor.redact_http_body_with_content_type_text(
            capture,
            Some("application/x-www-form-urlencoded"),
        );
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_http_multipart_name_limit_rejects_before_publication() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"abcd\"\r\n\r\nrejected-value-427\r\n--boundary--\r\n";
        let capture = BodyCapture::complete(body);
        let content_type = Some("multipart/form-data; boundary=boundary");
        let valid = Redactor::new(policy_with_key_limit(32));
        assert!(
            valid
                .inspect_http_body_with_content_type_text(capture, content_type)
                .is_ok()
        );
        assert_rejected(redactor.redact_http_body_with_content_type_text(capture, content_type));
        let error = redactor
            .inspect_http_body_with_content_type_text(capture, content_type)
            .expect_err("oversized multipart name must make inspection inconclusive");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }
}
