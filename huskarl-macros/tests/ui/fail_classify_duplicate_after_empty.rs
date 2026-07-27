#[derive(Debug, huskarl_macros::Classify)]
enum Cause {
    #[classify()]
    #[classify(no)]
    Invalid,
}

fn main() {}
