#[derive(Debug, huskarl_macros::Classify)]
enum Cause {
    #[classify(no, retry)]
    Invalid,
}

fn main() {}
