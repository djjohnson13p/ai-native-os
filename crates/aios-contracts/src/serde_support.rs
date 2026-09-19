use serde::{Deserialize, Deserializer};

pub(crate) fn default_true() -> bool {
    true
}

/// Deserialize an optional property while rejecting explicit JSON `null`.
///
/// Serde normally maps both an absent property and a present `null` to
/// `Option::None`. Several AIOS schemas permit omission but not `null`, so
/// those fields use this helper together with `#[serde(default)]`.
pub(crate) fn deserialize_non_null_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Deserialize a required property whose schema explicitly permits `null`.
///
/// Using this function without `#[serde(default)]` keeps an absent property
/// distinct from a property that is present with a null value.
pub(crate) fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
