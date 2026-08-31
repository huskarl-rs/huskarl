use std::fmt;

#[derive(Debug)]
struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("crate-local")
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
struct Nested(::huskarl_core::Error);

impl fmt::Display for Nested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("nested")
    }
}

impl std::error::Error for Nested {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

mod foreign {
    #[derive(Debug)]
    pub struct Error;

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("foreign")
        }
    }

    impl std::error::Error for Error {}
}

#[derive(Debug, huskarl_macros::Classify)]
enum QualifiedCause {
    Core(::huskarl_core::Error),
    #[classify(no)]
    Io(std::io::Error),
    #[classify(retry)]
    Foreign(foreign::Error),
    #[classify(no)]
    CrateLocal(crate::Error),
    #[classify(with = QualifiedCause::nested_origin)]
    Nested(Nested),
}

impl QualifiedCause {
    fn nested_origin(source: &Nested) -> huskarl_core::error::propagation::Origin<'_> {
        huskarl_core::error::propagation::Origin::Propagates(&source.0)
    }
}

impl fmt::Display for QualifiedCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("qualified cause")
    }
}

impl std::error::Error for QualifiedCause {}

fn main() {
    let inner = huskarl_core::Error::new(huskarl_core::RetryAdvice::RETRY, "inner");
    let propagated: huskarl_core::Error = QualifiedCause::Core(inner).into();
    assert_eq!(propagated.retry_advice(), huskarl_core::RetryAdvice::RETRY);

    let io: huskarl_core::Error = QualifiedCause::Io(std::io::Error::other("leaf")).into();
    assert_eq!(io.retry_advice(), huskarl_core::RetryAdvice::No);

    let foreign: huskarl_core::Error = QualifiedCause::Foreign(foreign::Error).into();
    assert_eq!(foreign.retry_advice(), huskarl_core::RetryAdvice::RETRY);

    let crate_local: huskarl_core::Error = QualifiedCause::CrateLocal(crate::Error).into();
    assert_eq!(crate_local.retry_advice(), huskarl_core::RetryAdvice::No);

    let inner = huskarl_core::Error::new(huskarl_core::RetryAdvice::RETRY, "nested inner");
    let nested: huskarl_core::Error = QualifiedCause::Nested(Nested(inner)).into();
    assert_eq!(nested.retry_advice(), huskarl_core::RetryAdvice::RETRY);
}
