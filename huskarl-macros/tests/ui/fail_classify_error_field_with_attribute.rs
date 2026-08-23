#[derive(Debug, huskarl_macros::Classify)]
enum Cause {
    #[classify(no)]
    Wrapped { source: huskarl_core::Error },
}

fn main() {}
