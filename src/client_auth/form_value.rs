use std::borrow::Cow;

use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;

#[derive(Debug, Clone)]
pub enum FormValue<'a> {
    NonSensitive(Cow<'a, str>),
    Sensitive(Cow<'a, SecretString>),
}

impl From<String> for FormValue<'_> {
    fn from(value: String) -> Self {
        Self::NonSensitive(Cow::Owned(value))
    }
}

impl<'a> From<&'a str> for FormValue<'a> {
    fn from(value: &'a str) -> Self {
        Self::NonSensitive(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a SecretString> for FormValue<'a> {
    fn from(value: &'a SecretString) -> Self {
        Self::Sensitive(Cow::Borrowed(value))
    }
}

impl From<SecretString> for FormValue<'_> {
    fn from(value: SecretString) -> Self {
        Self::Sensitive(Cow::Owned(value))
    }
}

impl Serialize for FormValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FormValue::NonSensitive(cow) => cow.serialize(serializer),
            FormValue::Sensitive(secret_box) => secret_box.expose_secret().serialize(serializer),
        }
    }
}
