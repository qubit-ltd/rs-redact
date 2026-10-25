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

#[cfg(feature = "http")]
fn policy_with_key_and_collection_limits(
    key_bytes: usize,
    collection_items: usize,
) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_key_bytes(key_bytes)
                .max_collection_items(collection_items);
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
fn test_env_zero_key_limit_admits_only_the_empty_name() {
    let redactor = Redactor::new(policy_with_key_limit(0));
    assert!(redactor.redact_env("", "value").complete_text().is_ok());
    let output = redactor.redact_env("A", "rejected-value-427");
    assert!(!output.text().as_str().contains("rejected-value-427"));
    assert!(output.complete_text().is_err());
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

#[cfg(unix)]
#[test]
fn test_non_utf8_environment_name_uses_secret_fallback_without_key_rejection() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let name = OsString::from_vec(vec![b'N', 0xff]);
    let redactor = Redactor::new(policy_with_key_limit(0));
    let output =
        redactor.redact_env_pairs([(name.as_os_str(), OsStr::new("non-utf8-secret-value"))]);
    assert!(output.complete_text().is_ok());
    assert!(!output.text().as_str().contains("non-utf8-secret-value"));
    assert!(
        !output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    let inspected = redactor
        .inspect_env_pairs([(name.as_os_str(), OsStr::new("non-utf8-secret-value"))])
        .expect("non-UTF-8 name remains conclusively classified as secret");
    assert_eq!(
        inspected.max_sensitivity(),
        Some(qubit_redact::Sensitivity::Secret)
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

    #[test]
    fn test_uri_unicode_key_limit_counts_pre_normalization_utf8_bytes() {
        let redactor = Redactor::new(policy_with_key_limit(2));
        let output = redactor.redact_uri("https://example.test/?%C4%B0=value");
        assert!(output.complete_text().is_ok());
        redactor
            .inspect_uri("https://example.test/?%C4%B0=value")
            .expect("two decoded UTF-8 bytes fit before key normalization");
    }

    #[test]
    fn test_uri_query_marker_in_fragment_does_not_trigger_key_admission() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        let input = "https://example.test/#?abcd=value";
        assert!(redactor.redact_uri(input).complete_text().is_ok());
        redactor
            .inspect_uri(input)
            .expect("a question mark in the fragment does not start a query");
    }

    #[test]
    fn test_uri_disabled_policy_still_enforces_key_limit() {
        let mut policy = policy_with_key_limit(1);
        let _ = policy.set_disabled(true);
        let redactor = Redactor::new(policy);
        let input = "https://example.test/?abcd=rejected-value-427";
        let output = redactor.redact_uri(input);
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        let error = redactor
            .inspect_uri(input)
            .expect_err("limits apply when redaction is disabled");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_uri_key_limit_applies_to_composer_and_batch() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        let input = "https://example.test/?abcd=rejected-value-427";
        let composed = redactor
            .text_composer()
            .uri(|uri| {
                uri.value(input);
            })
            .finish();
        assert!(!composed.text().as_str().contains("rejected-value-427"));
        assert!(composed.complete_text().is_err());
        assert!(
            composed
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );

        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_uri(input);
        let output = batch.finish_with_marker("<redaction incomplete>");
        assert_eq!(output.text(handle).as_str(), "<redaction incomplete>");
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }
}

#[cfg(feature = "http")]
mod http {
    use super::policy_with_key_and_collection_limits;
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
    fn test_http_url_percent_decoding_defines_key_length() {
        let one_byte = Redactor::new(policy_with_key_limit(1));
        assert!(
            one_byte
                .redact_http_url("https://example.test/?%61=value")
                .complete_text()
                .is_ok()
        );

        let three_bytes = Redactor::new(policy_with_key_limit(3));
        let output = three_bytes.redact_http_url("https://example.test/?a%62cd=rejected-value-427");
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        let error = three_bytes
            .inspect_http_url("https://example.test/?a%62cd=rejected-value-427")
            .expect_err("decoded four-byte key exceeds the limit");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_http_url_and_headers_disabled_policy_still_enforce_key_limit() {
        let mut policy = policy_with_key_limit(1);
        let _ = policy.set_disabled(true);
        let redactor = Redactor::new(policy);
        let output = redactor.redact_http_url("https://example.test/?abcd=rejected-value-427");
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        let error = redactor
            .inspect_http_url("https://example.test/?abcd=rejected-value-427")
            .expect_err("HTTP URL limits apply when redaction is disabled");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );

        let mut headers = HeaderMap::new();
        headers.insert("abcd", HeaderValue::from_static("rejected-value-427"));
        let output = redactor.redact_http_headers(&headers);
        assert!(!output.text().as_str().contains("rejected-value-427"));
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        let error = redactor
            .inspect_http_headers(&headers)
            .expect_err("HTTP header limits apply when redaction is disabled");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }

    #[test]
    fn test_http_url_key_limit_applies_to_composer_and_batch() {
        let redactor = Redactor::new(policy_with_key_limit(1));
        let input = "https://example.test/?abcd=rejected-value-427";
        let composed = redactor
            .text_composer()
            .http(|http| {
                http.url(input);
            })
            .finish();
        assert!(!composed.text().as_str().contains("rejected-value-427"));
        assert!(composed.complete_text().is_err());
        assert!(
            composed
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );

        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_http_url(input);
        let output = batch.finish_with_marker("<redaction incomplete>");
        assert_eq!(output.text(handle).as_str(), "<redaction incomplete>");
        assert!(
            output
                .summary()
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
    fn test_http_form_plus_decoding_fits_three_bytes() {
        let redactor = Redactor::new(policy_with_key_limit(3));
        let capture = BodyCapture::complete(b"a+b=value");
        let output = redactor.redact_http_body_with_content_type_text(
            capture,
            Some("application/x-www-form-urlencoded"),
        );
        assert!(output.complete_text().is_ok());
        redactor
            .inspect_http_body_with_content_type_text(
                capture,
                Some("application/x-www-form-urlencoded"),
            )
            .expect("decoded key `a b` occupies three UTF-8 bytes");
    }

    #[test]
    fn test_invalid_form_preserves_segment_structure_accounting() {
        let redactor = Redactor::new(policy_with_key_and_collection_limits(16, 8));
        let capture = BodyCapture::complete(b"%GG=value");
        let output = redactor.redact_http_body_with_content_type_text(
            capture,
            Some("application/x-www-form-urlencoded"),
        );
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::InvalidForm)
        );
        assert!(
            !output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        assert_eq!(output.summary().usage().visited_collection_items(), 1);
    }

    #[test]
    fn test_invalid_form_limit_failure_keeps_traversal_reason() {
        let redactor = Redactor::new(policy_with_key_and_collection_limits(16, 1));
        let capture = BodyCapture::complete(b"first=value&%GG=invalid");
        let output = redactor.redact_http_body_with_content_type_text(
            capture,
            Some("application/x-www-form-urlencoded"),
        );
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        assert!(
            !output
                .summary()
                .reasons()
                .contains(RedactionReason::InvalidForm)
        );
        assert_eq!(output.summary().usage().visited_collection_items(), 1);
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

    #[test]
    fn test_http_multipart_name_limit_precedes_filename_handling() {
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"TOO_LONG\"; filename=\"upload.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nfile-bytes\r\n--boundary--\r\n";
        let capture = BodyCapture::complete(body);
        let content_type = Some("multipart/form-data; boundary=boundary");
        let valid = Redactor::new(policy_with_key_limit(32));
        assert!(
            valid
                .inspect_http_body_with_content_type_text(capture, content_type)
                .is_ok()
        );

        let limited = Redactor::new(policy_with_key_limit(1));
        assert_rejected(limited.redact_http_body_with_content_type_text(capture, content_type));
        let error = limited
            .inspect_http_body_with_content_type_text(capture, content_type)
            .expect_err("multipart name admission applies before the filename branch");
        assert!(
            error
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
    }
}
