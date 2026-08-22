use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

struct Example {
    secret: String,
    omitted: String,
}

impl Redact for Example {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Example", |fields| {
            fields.sensitive(Sensitivity::Secret, "secret", || &self.secret);
            fields.skipped("omitted", || &self.omitted);
        });
    }
}

#[test]
fn disabled_policy_preserves_configuration_through_builder() {
    let mut policy = RedactionPolicy::standard();
    assert!(!policy.is_disabled());
    assert!(policy.set_disabled(true).is_disabled());
    assert!(RedactionPolicy::disabled().is_disabled());
    assert!(policy.to_builder().build().expect("policy is valid").is_disabled());
    assert!(!policy.set_disabled(false).is_disabled());
}

#[test]
fn disabled_policy_outputs_scalar_and_domain_values_without_redaction() {
    let output = Redactor::new(RedactionPolicy::disabled()).redact_field("password", "raw-secret");
    assert!(output.text().as_str().contains("raw-secret"));
    assert!(output.summary().is_redaction_disabled());

    let value = Example {
        secret: "raw-secret".into(),
        omitted: "restored".into(),
    };
    let output = Redactor::new(RedactionPolicy::disabled()).redact(&value);
    assert!(output.text().as_str().contains("raw-secret"));
    assert!(output.text().as_str().contains("restored"));
    assert!(output.summary().is_redaction_disabled());
}

#[test]
fn disabled_inspection_is_explicit() {
    let inspection = Redactor::new(RedactionPolicy::disabled())
        .inspect_field("password", "raw-secret")
        .expect("disabled inspection remains conclusive");
    assert!(inspection.is_redaction_disabled());
}
