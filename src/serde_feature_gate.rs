#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_serde {
    ($($tokens:tt)*) => { $($tokens)* };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __qubit_redact_serde {
    ($($tokens:tt)*) => {
        compile_error!(
            "#[redact(serde)] requires the `serde` feature of qubit-redact"
        );
    };
}
