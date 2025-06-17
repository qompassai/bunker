mod deserializer;
mod serializer;

#[cfg(test)]
mod tests;

use std::fmt::Display;
use std::result::Result as StdResult;

use displaydoc::Display;
use serde::{Deserialize, Serialize, de, ser};
use serde_with::{StringWithSeparator, formats::SpaceSeparator};

use crate::error::{ErrorKind, ServerResult};
use deserializer::Deserializer;
use serializer::Serializer;

type Result<T> = StdResult<T, Error>;

pub fn from_str<T>(s: &str) -> ServerResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    let mut deserializer = Deserializer::from_str(s);
    T::deserialize(&mut deserializer).map_err(|e| ErrorKind::ManifestSerializationError(e).into())

    // FIXME: Reject extra output??
}

pub fn to_string<T>(value: &T) -> ServerResult<String>
where
    T: Serialize,
{
    let mut serializer = Serializer::new();
    value
        .serialize(&mut serializer)
        .map_err(ErrorKind::ManifestSerializationError)?;

    Ok(serializer.into_output())
}

#[derive(Debug, Display)]
pub enum Error {
    Unexpected(&'static str),

    UnexpectedEof,

    ExpectedColon,

    ExpectedBoolean,

    ExpectedInteger,

    Unsupported(&'static str),

    AnyUnsupported,

    NoneUnsupported,

    NestedMapUnsupported,

    FloatUnsupported,

    Custom(String),
}

pub type SpaceDelimitedList = StringWithSeparator<SpaceSeparator, String>;

impl std::error::Error for Error {}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        let f = format!("{}", msg);
        Self::Custom(f)
    }
}

impl ser::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        let f = format!("{}", msg);
        Self::Custom(f)
    }
}
