use std::fmt;

#[derive(Debug, huskarl_macros::Classify)]
enum GenericCause<T>
where
    T: fmt::Debug + fmt::Display + Send + Sync + 'static,
{
    #[classify(no)]
    Leaf(T),
    Wrapped(huskarl_core::Error),
}

impl<T> fmt::Display for GenericCause<T>
where
    T: fmt::Debug + fmt::Display + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "generic cause")
    }
}

impl<T> std::error::Error for GenericCause<T> where
    T: fmt::Debug + fmt::Display + Send + Sync + 'static
{
}

fn main() {
    let error: huskarl_core::Error = GenericCause::Leaf("leaf").into();
    assert_eq!(error.retry_advice(), huskarl_core::RetryAdvice::No);
}
