#![cfg(feature = "http")]

use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

const BODY: &[u8] = concat!(
    "--b\r\n",
    "Content-Disposition: form-data; name=\"payload\"\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
    "x=1\r\n--b--\r\n",
)
.as_bytes();

fn redactor(depth: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(depth);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    Redactor::new(policy)
}

#[test]
fn test_multipart_nested_form_depth_matches_rendering_and_inspection() {
    let content_type = "multipart/form-data; boundary=b";
    let shallow = redactor(2);
    let inspected = shallow
        .inspect_http_body_with_content_type_text(BodyCapture::complete(BODY), Some(content_type))
        .expect_err("nested field should exceed depth two");
    assert!(
        inspected
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );
    let rendered = shallow
        .redact_http_body_with_content_type_text(BodyCapture::complete(BODY), Some(content_type));
    assert!(
        rendered
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );

    let sufficient = redactor(3);
    let inspected = sufficient
        .inspect_http_body_with_content_type_text(BodyCapture::complete(BODY), Some(content_type))
        .expect("nested field should fit depth three");
    assert_eq!(inspected.usage().max_depth(), 3);
    sufficient
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(b"x=1"),
            Some("application/x-www-form-urlencoded"),
        )
        .expect("top-level form remains at depth two");
}
