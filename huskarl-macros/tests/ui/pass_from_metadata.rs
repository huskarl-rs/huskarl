//! Verifies `#[from_metadata]` end-to-end with real `bon`, covering:
//! - direct path
//! - nested-through-Option path
//! - `with =` escape hatch
//! - gating field (required-on-target draws from Option-in-source) →
//!   `Result<Builder<…>, huskarl_core::Error>` naming the absent field.

#[derive(Debug)]
struct Meta {
    name: String,
    nested: Option<Inner>,
    required_in_target: Option<u32>,
    counter: u32,
}

#[derive(Debug)]
struct Inner {
    value: Option<String>,
}

/// Separate module so each `#[derive(Builder)]` gets its own `builder`
/// state module without colliding with the other test target.
mod without_gate {
    use bon::Builder;

    use super::Meta;

    #[huskarl_macros::from_metadata(metadata = crate::Meta)]
    #[derive(Builder)]
    #[builder(state_mod(name = "builder"))]
    pub struct WithoutGate {
        #[from_metadata(path = "name")]
        pub name: Option<String>,

        #[from_metadata(path = "nested?.value?")]
        pub nested_value: Option<String>,

        // Default `with` semantics: closure yields `T`; bon's `counter_plus_one`
        // setter wraps the `u32` in `Some` for the `Option<u32>` field.
        #[from_metadata(with = |m: &Meta| m.counter + 1)]
        pub counter_plus_one: Option<u32>,

        // `maybe` opt-in: closure yields `Option<T>`; bon's `maybe_counter_doubled`
        // setter takes the `Option<u32>` directly.
        #[from_metadata(with = |m: &Meta| m.required_in_target.map(|c| c * 2), maybe)]
        pub counter_doubled: Option<u32>,
    }
}

mod with_gate {
    use bon::Builder;

    #[huskarl_macros::from_metadata(metadata = crate::Meta)]
    #[derive(Builder)]
    #[builder(state_mod(name = "builder"))]
    pub struct WithGate {
        #[from_metadata(path = "name")]
        pub name: Option<String>,

        #[from_metadata(path = "required_in_target?")]
        pub required_in_target: u32,
    }
}

/// Regression: two `#[from_metadata]` structs in the same module must not
/// collide on the generated state-alias name.
mod two_in_one_module {
    use bon::Builder;

    #[huskarl_macros::from_metadata(metadata = crate::Meta)]
    #[derive(Builder)]
    #[builder(state_mod(name = "first_builder"))]
    pub struct First {
        #[from_metadata(path = "name")]
        pub name: Option<String>,
    }

    #[huskarl_macros::from_metadata(metadata = crate::Meta)]
    #[derive(Builder)]
    #[builder(state_mod(name = "second_builder"))]
    pub struct Second {
        #[from_metadata(path = "name")]
        pub name: Option<String>,
    }
}

/// Regression: generic type parameter with a `where` clause — the macro must
/// splice the `where` clause onto the generated `impl` head, not drop it.
mod with_where_clause {
    use bon::Builder;

    pub trait Tag {}
    impl Tag for () {}

    #[huskarl_macros::from_metadata(metadata = crate::Meta)]
    #[derive(Builder)]
    #[builder(state_mod(name = "builder"))]
    pub struct WithWhere<T>
    where
        T: Tag + Default + 'static,
    {
        #[from_metadata(path = "name")]
        pub name: Option<String>,

        #[builder(default)]
        pub tag: T,
    }
}

use two_in_one_module::{First, Second};
use with_gate::WithGate;
use with_where_clause::WithWhere;
use without_gate::WithoutGate;

fn main() {
    let meta = Meta {
        name: "hello".to_owned(),
        nested: Some(Inner {
            value: Some("inner".to_owned()),
        }),
        required_in_target: Some(42),
        counter: 9,
    };
    let built = WithoutGate::builder_from_metadata(&meta).build();
    assert_eq!(built.name.as_deref(), Some("hello"));
    assert_eq!(built.nested_value.as_deref(), Some("inner"));
    assert_eq!(built.counter_plus_one, Some(10));
    assert_eq!(built.counter_doubled, Some(84));

    let meta_none = Meta {
        name: "hi".to_owned(),
        nested: None,
        required_in_target: None,
        counter: 0,
    };
    let built = WithoutGate::builder_from_metadata(&meta_none).build();
    assert_eq!(built.nested_value, None);
    assert_eq!(built.counter_doubled, None);

    let gated = WithGate::builder_from_metadata(&meta);
    let built = gated.unwrap().build();
    assert_eq!(built.required_in_target, 42);

    // `.err()`, not `unwrap_err()`: bon builders aren't `Debug`.
    let err = WithGate::builder_from_metadata(&meta_none)
        .err()
        .expect("required_in_target absent");
    assert_eq!(err.retry_advice(), huskarl_core::RetryAdvice::No);
    assert_eq!(
        format!("{err:#}"),
        "authorization server metadata has no 'required_in_target'"
    );

    let built = WithWhere::<()>::builder_from_metadata(&meta).build();
    assert_eq!(built.name.as_deref(), Some("hello"));

    let first = First::builder_from_metadata(&meta).build();
    let second = Second::builder_from_metadata(&meta).build();
    assert_eq!(first.name.as_deref(), Some("hello"));
    assert_eq!(second.name.as_deref(), Some("hello"));
}
