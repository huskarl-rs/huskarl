//! Verifies that `#[try_builder]` and `#[from_metadata]` work on a
//! `#[bon::bon]` impl block — i.e. when the bon builder is derived from a
//! `fn new`'s arguments rather than from struct fields.

#[derive(Debug, PartialEq, Eq)]
struct Url(String);

trait IntoUrl {
    fn into_url(self) -> Result<Url, huskarl_core::Error>;
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url, huskarl_core::Error> {
        if self.is_empty() {
            Err(huskarl_core::ErrorKind::Config.into())
        } else {
            Ok(Url(self.to_owned()))
        }
    }
}

#[derive(Debug)]
struct Meta {
    label: String,
    count_in_source: Option<u32>,
    nested: Option<Inner>,
}

#[derive(Debug)]
struct Inner {
    value: Option<u32>,
}

#[derive(Debug)]
struct Widget {
    primary: Url,
    label: Option<String>,
    count: Option<u32>,
    nested_count: Option<u32>,
}

#[huskarl_macros::from_metadata(metadata = crate::Meta)]
#[huskarl_macros::try_builder]
#[bon::bon]
impl Widget {
    #[builder(state_mod(name = "builder"), on(String, into))]
    pub fn new(
        #[try_setter(crate::IntoUrl::into_url)] primary: Url,

        #[from_metadata(path = "label")] label: Option<String>,

        #[from_metadata(path = "count_in_source?")] count: Option<u32>,

        #[from_metadata(path = "nested?.value?")] nested_count: Option<u32>,
    ) -> Self {
        Self {
            primary,
            label,
            count,
            nested_count,
        }
    }
}

/// Regression: `Self` carries concrete type arguments (`Pinned<u32, T>`) that
/// don't match the impl's generic parameter list (`<T>`). The macro must use
/// `Self`'s literal arguments when emitting `impl … Pinned<…>`, not the impl's
/// own generic parameters.
#[derive(Debug)]
struct Pinned<U, T> {
    label: Option<String>,
    pin: U,
    tag: T,
}

#[huskarl_macros::from_metadata(metadata = crate::Meta)]
#[bon::bon]
impl<T: Default + 'static> Pinned<u32, T> {
    #[builder(state_mod(name = "pinned_builder"))]
    pub fn new(#[from_metadata(path = "label")] label: Option<String>) -> Self {
        Self {
            label,
            pin: 0,
            tag: T::default(),
        }
    }
}

fn main() {
    // -- Direct builder path: try_setter works on fn-mode args.
    let w = Widget::builder()
        .primary("https://example.com")
        .expect("parses")
        .label("hand-set".to_owned())
        .build();
    assert_eq!(w.primary, Url("https://example.com".to_owned()));
    assert_eq!(w.label.as_deref(), Some("hand-set"));

    // -- builder_from_metadata wires up the three from_metadata args.
    let meta = Meta {
        label: "from-metadata".to_owned(),
        count_in_source: Some(7),
        nested: Some(Inner { value: Some(42) }),
    };
    let w = Widget::builder_from_metadata(&meta)
        .primary("https://example.com")
        .expect("parses")
        .build();
    assert_eq!(w.label.as_deref(), Some("from-metadata"));
    assert_eq!(w.count, Some(7));
    assert_eq!(w.nested_count, Some(42));

    // -- nested path collapsing to None at any level yields None.
    let meta_none = Meta {
        label: "x".to_owned(),
        count_in_source: None,
        nested: None,
    };
    let w = Widget::builder_from_metadata(&meta_none)
        .primary("a")
        .unwrap()
        .build();
    assert_eq!(w.count, None);
    assert_eq!(w.nested_count, None);

    // -- Pinned<u32, T>: confirms Self's `u32` argument is preserved in the
    // generated impl head (and that bon's builder is reached as
    // `PinnedBuilder<u32, (), …>`).
    let p: Pinned<u32, ()> = Pinned::builder_from_metadata(&meta).build();
    assert_eq!(p.label.as_deref(), Some("from-metadata"));
    assert_eq!(p.pin, 0);
}
