//! Prints the coverage report: each provider and the flow variants it exercises.

fn main() {
    print!("{}", huskarl_integration::matrix::coverage_report());
}
