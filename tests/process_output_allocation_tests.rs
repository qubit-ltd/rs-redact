// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(unix)]

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::cell::Cell;
use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static MAX_REQUEST: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        Self::record(layout.size());
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        Self::record(size);
        result
    }
}

impl CountingAllocator {
    fn record(bytes: usize) {
        COUNTING.with(|counting| {
            if counting.get() {
                MAX_REQUEST.with(|maximum| maximum.set(maximum.get().max(bytes)));
            }
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn measure<T>(operation: impl FnOnce() -> T) -> (usize, T) {
    MAX_REQUEST.with(|maximum| maximum.set(0));
    COUNTING.with(|counting| counting.set(true));
    let result = operation();
    COUNTING.with(|counting| counting.set(false));
    (MAX_REQUEST.with(Cell::get), result)
}

fn bounded_redactor() -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(16);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    Redactor::new(policy)
}

fn bounded_disabled_redactor() -> Redactor {
    let policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_output_bytes(16);
        })
        .expect("limit draft should build")
        .build()
        .expect("disabled policy should build");
    Redactor::new(policy)
}

#[test]
fn test_large_public_utf8_argv_does_not_drive_intermediate_allocation() {
    let _ = Redactor::standard().redact_argv([ArgvItem::plain(OsStr::new("warmup"))]);
    let redactor = bounded_redactor();
    let small = "x".repeat(4 * 1024);
    let large = "x".repeat(48 * 1024);

    let (small_max, small_output) = measure(|| redactor.redact_argv([ArgvItem::plain(OsStr::new(&small))]));
    let (large_max, large_output) = measure(|| redactor.redact_argv([ArgvItem::plain(OsStr::new(&large))]));

    assert!(small_max < 4 * 1024, "4 KiB argv requested {small_max} bytes");
    assert!(large_max < 4 * 1024, "48 KiB argv requested {large_max} bytes");
    assert!(
        large_max <= small_max,
        "large argv request {large_max} exceeded small request {small_max}"
    );
    for output in [small_output, large_output] {
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert_eq!(output.text().as_str(), "<truncated>");
    }
}

#[test]
fn test_heuristic_inline_option_join_allocation_is_bounded() {
    let redactor = bounded_redactor();
    let _ = Redactor::standard().redact_heuristic_argv([ArgvItem::plain(OsStr::new("--password=x"))]);
    let small = format!("{}password=x", "-".repeat(4 * 1024));
    let large = format!("{}password=x", "-".repeat(48 * 1024));

    let (small_max, small_output) = measure(|| redactor.redact_heuristic_argv([ArgvItem::plain(OsStr::new(&small))]));
    let (large_max, large_output) = measure(|| redactor.redact_heuristic_argv([ArgvItem::plain(OsStr::new(&large))]));

    eprintln!("inline option maximum allocation: 4 KiB={small_max}, 48 KiB={large_max}");
    assert!(small_max < 4 * 1024, "4 KiB option requested {small_max} bytes");
    assert!(large_max < 4 * 1024, "48 KiB option requested {large_max} bytes");
    assert!(
        large_max <= small_max,
        "large option request {large_max} exceeded small request {small_max}"
    );
    for output in [small_output, large_output] {
        assert_eq!(output.text().as_str(), "<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    }
}

#[test]
fn test_heuristic_assignment_join_allocation_is_bounded() {
    let redactor = bounded_redactor();
    let _ = Redactor::standard().redact_heuristic_argv([ArgvItem::plain(OsStr::new("password=x"))]);
    let small = format!("password{}=x", " ".repeat(4 * 1024));
    let large = format!("password{}=x", " ".repeat(48 * 1024));

    let (small_max, small_output) = measure(|| redactor.redact_heuristic_argv([ArgvItem::plain(OsStr::new(&small))]));
    let (large_max, large_output) = measure(|| redactor.redact_heuristic_argv([ArgvItem::plain(OsStr::new(&large))]));

    eprintln!("assignment maximum allocation: 4 KiB={small_max}, 48 KiB={large_max}");
    assert!(small_max < 4 * 1024, "4 KiB assignment requested {small_max} bytes");
    assert!(large_max < 4 * 1024, "48 KiB assignment requested {large_max} bytes");
    assert!(
        large_max <= small_max,
        "large assignment request {large_max} exceeded small request {small_max}"
    );
    for output in [small_output, large_output] {
        assert_eq!(output.text().as_str(), "<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    }
}

#[test]
fn test_heuristic_jvm_property_join_allocation_is_bounded() {
    let redactor = bounded_redactor();
    let _ = Redactor::standard().redact_heuristic_argv([ArgvItem::plain(OsStr::new("-Dpassword=x"))]);
    let small = format!("-Dpassword{}=x", " ".repeat(4 * 1024));
    let large = format!("-Dpassword{}=x", " ".repeat(48 * 1024));

    let (small_max, small_output) = measure(|| redactor.redact_heuristic_argv([ArgvItem::plain(OsStr::new(&small))]));
    let (large_max, large_output) = measure(|| redactor.redact_heuristic_argv([ArgvItem::plain(OsStr::new(&large))]));

    eprintln!("JVM property maximum allocation: 4 KiB={small_max}, 48 KiB={large_max}");
    assert!(small_max < 4 * 1024, "4 KiB property requested {small_max} bytes");
    assert!(large_max < 4 * 1024, "48 KiB property requested {large_max} bytes");
    assert!(
        large_max <= small_max,
        "large property request {large_max} exceeded small request {small_max}"
    );
    for output in [small_output, large_output] {
        assert_eq!(output.text().as_str(), "<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    }
}

#[test]
fn test_large_public_utf8_env_value_does_not_drive_intermediate_allocation() {
    let _ = Redactor::standard().redact_env("PUBLIC_VALUE", "warmup");
    let redactor = bounded_redactor();
    let small = "x".repeat(4 * 1024);
    let large = "x".repeat(48 * 1024);

    let (small_max, small_output) = measure(|| redactor.redact_env("PUBLIC_VALUE", &small));
    let (large_max, large_output) = measure(|| redactor.redact_env("PUBLIC_VALUE", &large));

    assert!(small_max < 4 * 1024, "4 KiB env value requested {small_max} bytes");
    assert!(large_max < 4 * 1024, "48 KiB env value requested {large_max} bytes");
    assert!(
        large_max <= small_max,
        "large env request {large_max} exceeded small request {small_max}"
    );
    for output in [small_output, large_output] {
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert_eq!(output.text().as_str(), "<truncated>");
    }
}

#[cfg(unix)]
#[test]
fn test_non_utf8_argv_and_env_capture_allocation_is_output_bounded() {
    let enabled = Redactor::standard();
    let disabled = bounded_disabled_redactor();
    let _ = enabled.redact_argv([ArgvItem::plain(OsStr::new("warmup"))]);
    let _ = disabled.redact_argv([ArgvItem::plain(OsStr::new("warmup"))]);
    let _ = enabled.redact_env_pairs([(OsStr::new("N"), OsStr::new("v"))]);
    let _ = disabled.redact_env_pairs([(OsStr::new("N"), OsStr::new("v"))]);
    let redactor = bounded_redactor();
    let small = OsString::from_vec([vec![b'x'; 4 * 1024], vec![0xff]].concat());
    let large = OsString::from_vec([vec![b'x'; 48 * 1024], vec![0xff]].concat());
    let small_name = OsString::from_vec([vec![b'N'; 4 * 1024], vec![0xff]].concat());
    let large_name = OsString::from_vec([vec![b'N'; 48 * 1024], vec![0xff]].concat());

    let (small_argv_max, small_argv) = measure(|| redactor.redact_argv([ArgvItem::plain(&small)]));
    let (large_argv_max, large_argv) = measure(|| redactor.redact_argv([ArgvItem::plain(&large)]));
    let (small_disabled_max, small_disabled) = measure(|| disabled.redact_argv([ArgvItem::plain(&small)]));
    let (large_disabled_max, large_disabled) = measure(|| disabled.redact_argv([ArgvItem::plain(&large)]));
    let (small_name_max, small_name_output) =
        measure(|| redactor.redact_env_pairs([(small_name.as_os_str(), OsStr::new("v"))]));
    let (large_name_max, large_name_output) =
        measure(|| redactor.redact_env_pairs([(large_name.as_os_str(), OsStr::new("v"))]));
    let (small_value_max, small_value_output) =
        measure(|| disabled.redact_env_pairs([(OsStr::new("N"), small.as_os_str())]));
    let (large_value_max, large_value_output) =
        measure(|| disabled.redact_env_pairs([(OsStr::new("N"), large.as_os_str())]));

    for (label, maximum) in [
        ("small argv", small_argv_max),
        ("large argv", large_argv_max),
        ("small disabled argv", small_disabled_max),
        ("large disabled argv", large_disabled_max),
        ("small env name", small_name_max),
        ("large env name", large_name_max),
        ("small env value", small_value_max),
        ("large env value", large_value_max),
    ] {
        assert!(maximum < 4 * 1024, "{label} requested {maximum} bytes");
    }
    for (small, large) in [
        (small_argv_max, large_argv_max),
        (small_disabled_max, large_disabled_max),
        (small_name_max, large_name_max),
        (small_value_max, large_value_max),
    ] {
        assert!(large <= small, "48 KiB request {large} exceeded 4 KiB request {small}");
    }
    for output in [
        small_argv,
        large_argv,
        small_disabled,
        large_disabled,
        small_name_output,
        large_name_output,
        small_value_output,
        large_value_output,
    ] {
        assert_eq!(output.text().as_str(), "<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert!(!output.summary().reasons().contains(RedactionReason::InputLimitReached));
    }
}

#[test]
fn test_repeated_escaping_stays_bounded_before_publishing_truncated_output() {
    let _ = Redactor::standard().redact_env("PUBLIC_VALUE", "warmup");
    let redactor = bounded_redactor();
    let small = "\n\\".repeat(2 * 1024);
    let large = "\n\\".repeat(24 * 1024);

    let (small_argv_max, small_argv) = measure(|| redactor.redact_argv([ArgvItem::plain(OsStr::new(&small))]));
    let (large_argv_max, large_argv) = measure(|| redactor.redact_argv([ArgvItem::plain(OsStr::new(&large))]));
    let (small_env_max, small_env) = measure(|| redactor.redact_env("PUBLIC_VALUE", &small));
    let (large_env_max, large_env) = measure(|| redactor.redact_env("PUBLIC_VALUE", &large));

    for maximum in [small_argv_max, large_argv_max, small_env_max, large_env_max] {
        assert!(maximum < 4 * 1024, "escaping path requested {maximum} bytes");
    }
    assert!(large_argv_max <= small_argv_max);
    assert!(large_env_max <= small_env_max);
    for output in [small_argv, large_argv, small_env, large_env] {
        assert_eq!(output.text().as_str(), "<truncated>");
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert!(!output.text().as_str().contains('\n'));
    }
}

#[test]
fn test_argv_and_env_keep_complete_unicode_and_debug_escaping() {
    let redactor = Redactor::standard();
    let argv = redactor.redact_argv([ArgvItem::plain(OsStr::new("a\"\\\n e\u{301}雪"))]);
    let env_value = "a\"\\\n e\u{301}雪";
    let env = redactor.redact_env("PUBLIC_VALUE", env_value);

    assert_eq!(argv.text().as_str(), format!("[{:?}]", env_value));
    assert_eq!(env.text().as_str(), "PUBLIC_VALUE=a\"\\\\n e\u{301}雪");
    assert_eq!(argv.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(env.summary().completion(), RedactionCompletion::Complete);
}

#[cfg(unix)]
#[test]
fn test_small_non_utf8_process_text_matches_lossy_legacy_representation() {
    let redactor = Redactor::new(RedactionPolicy::disabled());
    let bytes = b"quote\"\\\n e\xcc\x81 \xe9\x9b\xaa \xf0\x9f\x92\xff\xfe";
    let value = OsString::from_vec(bytes.to_vec());
    let lossy = value.to_string_lossy();

    let argv = redactor.redact_argv([ArgvItem::plain(&value)]);
    assert_eq!(argv.text().as_str(), format!("[{lossy:?}]"));
    assert_eq!(argv.summary().completion(), RedactionCompletion::Complete);

    let env_value = OsString::from_vec(vec![b'o', b'k', 0xff]);
    let env = redactor.redact_env_pairs([(OsStr::new("PUBLIC"), env_value.as_os_str())]);
    assert_eq!(env.text().as_str(), "[\"PUBLIC=ok�\"]");
    assert_eq!(env.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn test_capacity_edges_composer_batch_disabled_and_non_utf8_paths() {
    for (maximum, expected, completion) in [
        (0, "", RedactionCompletion::Exhausted),
        (10, "", RedactionCompletion::Exhausted),
        (11, "<truncated>", RedactionCompletion::Truncated),
        (12, "<truncated>", RedactionCompletion::Truncated),
        (13, r#"["123456789"]"#, RedactionCompletion::Complete),
        (16, r#"["123456789"]"#, RedactionCompletion::Complete),
    ] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_output_bytes(maximum);
            })
            .expect("limit draft should build")
            .build()
            .expect("policy should build");
        let output = Redactor::new(policy).redact_argv([ArgvItem::plain(OsStr::new("123456789"))]);
        assert_eq!(output.text().as_str(), expected, "capacity {maximum}");
        assert_eq!(output.summary().completion(), completion, "capacity {maximum}");
        if completion != RedactionCompletion::Complete {
            assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        }
    }

    let redactor = Redactor::standard();
    let composed = redactor
        .text_composer()
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("x"))]);
        })
        .env(|env| {
            env.pair("PUBLIC_VALUE", "x");
        })
        .finish();
    assert_eq!(composed.text().as_str(), "[\"x\"]PUBLIC_VALUE=x");
    assert_eq!(composed.summary().completion(), RedactionCompletion::Complete);

    let mut batch = redactor.diagnostic_batch();
    let argv = batch.redact_argv([ArgvItem::plain(OsStr::new("x"))]);
    let env = batch.redact_env("PUBLIC_VALUE", "x");
    let output = batch.finish();
    assert_eq!(output.text(argv).as_str(), r#"["x"]"#);
    assert_eq!(output.text(env).as_str(), "PUBLIC_VALUE=x");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);

    let disabled = Redactor::new(RedactionPolicy::disabled());
    assert!(
        disabled
            .redact_argv([ArgvItem::sensitive(
                OsStr::new("visible-secret"),
                qubit_redact::Sensitivity::Secret
            )])
            .text()
            .as_str()
            .contains("visible-secret")
    );
    assert!(
        disabled
            .redact_env("PUBLIC_VALUE", "visible-secret")
            .text()
            .as_str()
            .contains("visible-secret")
    );

    #[cfg(unix)]
    {
        let non_utf8 = OsString::from_vec(vec![b'x', 0xff]);
        let argv = redactor.redact_argv([ArgvItem::plain(&non_utf8)]);
        let env = redactor.redact_env_pairs([(OsStr::new("PUBLIC_VALUE"), non_utf8.as_os_str())]);
        assert!(argv.text().as_str().contains('�'));
        assert!(env.text().as_str().contains("redacted"));
        let disabled_env = disabled.redact_env_pairs([(OsStr::new("PUBLIC_VALUE"), non_utf8.as_os_str())]);
        assert!(disabled_env.text().as_str().contains('�'));
    }
}

#[test]
fn test_composer_and_batch_summaries_respect_limited_output_budget() {
    let redactor = bounded_redactor();

    let composer_argv = redactor
        .text_composer()
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("x"))]);
        })
        .finish();
    assert_eq!(composer_argv.text().as_str(), r#"["x"]"#);
    assert_eq!(composer_argv.summary().completion(), RedactionCompletion::Complete);
    assert!(composer_argv.summary().usage().output_bytes() <= 16);

    let composer_env = redactor
        .text_composer()
        .env(|env| {
            env.pair("PUBLIC_VALUE", "x");
        })
        .finish();
    assert_eq!(composer_env.text().as_str(), "PUBLIC_VALUE=x");
    assert_eq!(composer_env.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(composer_env.summary().usage().output_bytes(), 14);

    let mut batch = redactor.diagnostic_batch();
    let argv_handle = batch.redact_argv([ArgvItem::plain(OsStr::new("x"))]);
    let output = batch.finish_with_marker("<batch incomplete>");
    assert_eq!(output.text(argv_handle).as_str(), r#"["x"]"#);
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().usage().output_bytes() <= 16);

    let mut batch = redactor.diagnostic_batch();
    let env_handle = batch.redact_env("PUBLIC_VALUE", "x");
    let output = batch.finish_with_marker("<batch incomplete>");
    assert_eq!(output.text(env_handle).as_str(), "PUBLIC_VALUE=x");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().output_bytes(), 14);

    let long_value = format!("{}-private-source", "x".repeat(256));
    let composer_argv = redactor
        .text_composer()
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new(&long_value))]);
        })
        .finish();
    assert!(!composer_argv.text().as_str().contains(&long_value));
    assert_eq!(composer_argv.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        composer_argv
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert!(composer_argv.summary().usage().output_bytes() <= 16);

    let composer_env = redactor
        .text_composer()
        .env(|env| {
            env.pair("PUBLIC_VALUE", &long_value);
        })
        .finish();
    assert!(!composer_env.text().as_str().contains(&long_value));
    assert_eq!(composer_env.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        composer_env
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert!(composer_env.summary().usage().output_bytes() <= 16);

    let mut batch = redactor.diagnostic_batch();
    let argv_handle = batch.redact_argv([ArgvItem::plain(OsStr::new(&long_value))]);
    let output = batch.finish_with_marker("<batch incomplete>");
    assert!(!output.text(argv_handle).as_str().contains(&long_value));
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(output.summary().usage().output_bytes() <= 16);

    let mut batch = redactor.diagnostic_batch();
    let env_handle = batch.redact_env("PUBLIC_VALUE", &long_value);
    let output = batch.finish_with_marker("<batch incomplete>");
    assert!(!output.text(env_handle).as_str().contains(&long_value));
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(output.summary().usage().output_bytes() <= 16);
}
