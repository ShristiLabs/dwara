//! Unit tests for `extensions::ExtensionsError` (relocated from src).

use dwara_core::config::ConfigError;
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

// --- From conversions (#128) ----------------------------------------------

#[test]
fn from_io_error_maps_to_the_io_class() {
    let err = ExtensionsError::from(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no such file",
    ));
    assert_eq!(err, ExtensionsError::Io("no such file".into()));
    assert_eq!(err.to_string(), "extension io error: no such file");
}

#[test]
fn from_config_error_maps_to_invalid_preserving_the_path() {
    let err = ExtensionsError::from(ConfigError {
        path: "listeners[0].port".into(),
        message: "invalid type".into(),
    });
    assert_eq!(
        err,
        ExtensionsError::Invalid("config error at listeners[0].port: invalid type".into())
    );
}
