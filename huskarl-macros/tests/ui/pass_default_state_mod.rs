//! Verifies that `#[from_metadata]` works when the user omits
//! `#[builder(state_mod(name = "…"))]` — it falls back to bon's default,
//! which is snake_case of the builder type name (`{Struct}Builder` →
//! `{struct}_builder`).

#[derive(Debug)]
struct Src {
    name: String,
}

mod with_from_metadata {
    /// No `state_mod(name = "…")` — macro falls back to `record_builder`.
    #[huskarl_macros::from_metadata(metadata = crate::Src)]
    #[derive(bon::Builder)]
    pub struct Record {
        #[from_metadata(path = "name")]
        pub name: Option<String>,
    }
}

fn main() {
    let src = Src {
        name: "abc".to_owned(),
    };
    let r = with_from_metadata::Record::builder_from_metadata(&src).build();
    assert_eq!(r.name.as_deref(), Some("abc"));
}
