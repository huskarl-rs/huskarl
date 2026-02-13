use snafu::Snafu;

use crate::grant::core::form::OAuth2FormError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum StartError<
    AuthErr: crate::Error + 'static,
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
    JarErr: crate::Error + 'static,
> {
    Url {
        source: serde_html_form::ser::Error,
    },
    Par {
        source: OAuth2FormError<HttpErr, HttpRespErr, DPoPErr>,
    },
    Jar {
        source: JarErr,
    },
    ClientAuth {
        source: AuthErr,
    },
}

#[derive(Debug, Clone, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum CompleteError<GrantErr: crate::Error + 'static> {
    Grant { source: GrantErr },
    IssuerMismatch { original: String, callback: String },
    StateMismatch { original: String, callback: String },
    MissingIssuer,
}

impl<GrantErr: crate::Error + 'static> crate::Error for CompleteError<GrantErr> {
    fn is_retryable(&self) -> bool {
        match self {
            CompleteError::Grant { source } => source.is_retryable(),
            CompleteError::IssuerMismatch { .. }
            | CompleteError::StateMismatch { .. }
            | CompleteError::MissingIssuer => false,
        }
    }
}
