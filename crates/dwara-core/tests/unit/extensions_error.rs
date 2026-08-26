//! Unit tests for `extensions::ExtensionsError` (relocated from src).

use dwara_core::extensions::ExtensionsError;

#[test]
fn display_names_each_failure_class() {
    assert_eq!(
        ExtensionsError::Io("x".into()).to_string(),
        "extension io error: x"
    );
    assert_eq!(
        ExtensionsError::Invalid("y".into()).to_string(),
        "extension invalid-data error: y"
    );
    assert_eq!(
        ExtensionsError::Backend("z".into()).to_string(),
        "extension backend error: z"
    );
    assert_eq!(
        ExtensionsError::Unsupported("w".into()).to_string(),
        "extension unsupported operation: w"
    );
}

#[test]
fn error_impls_std_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(ExtensionsError::Backend("b".into()));
    assert_eq!(err.to_string(), "extension backend error: b");
}
