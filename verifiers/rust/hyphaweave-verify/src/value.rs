// SPDX-FileCopyrightText: 2026 Inceptless <support@inceptless.com>
// SPDX-License-Identifier: Apache-2.0

//! In-memory JSON value used by the verifier.
//!
//! The verifier parses its own JSON (see [`crate::json`]) because WR-CJ needs
//! duplicate-member rejection, integer-only numbers and exact first-violation
//! classification, which general-purpose JSON libraries do not provide. The
//! value tree keeps object members in input order; the canonical writer sorts
//! them itself.

/// A parsed JSON object. Member order follows the input; the canonical writer
/// sorts members by UTF-16 code units. Duplicate members never appear here:
/// the parser rejects them before constructing the object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

impl Object {
    /// Creates an empty object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the object has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Appends a member. Callers must not add a name twice; parsed objects are
    /// duplicate-free by construction and constructed reports use unique keys.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<Value>) {
        self.entries.push((name.into(), value.into()));
    }

    /// Returns the value of `name`, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }

    /// Returns the raw string of a member, if present and a string.
    #[must_use]
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(Value::as_str)
    }

    /// Returns a member object, if present and an object.
    #[must_use]
    pub fn get_object(&self, name: &str) -> Option<&Object> {
        self.get(name).and_then(Value::as_object)
    }

    /// Returns a member array, if present and an array.
    #[must_use]
    pub fn get_array(&self, name: &str) -> Option<&[Value]> {
        self.get(name).and_then(Value::as_array)
    }

    /// Returns a member integer, if present and an integer.
    #[must_use]
    pub fn get_i64(&self, name: &str) -> Option<i64> {
        self.get(name).and_then(Value::as_i64)
    }

    /// Returns a member boolean, if present and a boolean.
    #[must_use]
    pub fn get_bool(&self, name: &str) -> Option<bool> {
        self.get(name).and_then(Value::as_bool)
    }

    /// True when the member is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Iterates over members in input order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(key, value)| (key.as_str(), value))
    }

    /// Iterates over member names in input order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(key, _)| key.as_str())
    }

    /// Returns a copy without the named member.
    #[must_use]
    pub fn without(&self, name: &str) -> Self {
        let entries = self
            .entries
            .iter()
            .filter(|(key, _)| key != name)
            .cloned()
            .collect();
        Self { entries }
    }

    /// First member name that is not in `allowed`, in input order.
    #[must_use]
    pub fn first_unknown<'a, I>(&'a self, allowed: I) -> Option<&'a str>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let allowed: Vec<&str> = allowed.into_iter().collect();
        self.keys().find(|key| !allowed.contains(key))
    }
}

impl FromIterator<(String, Value)> for Object {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

/// A JSON value under the WR-CJ input restrictions: no floats, integers in
/// `[-(2^53-1), 2^53-1]`, no lone surrogates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// A WR-CJ integer.
    Int(i64),
    /// A JSON string.
    Str(String),
    /// A JSON array.
    Array(Vec<Value>),
    /// A JSON object.
    Object(Object),
}

impl Value {
    /// Returns the object, if this value is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    /// Returns the array, if this value is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the string, if this value is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the integer, if this value is an integer.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(number) => Some(*number),
            _ => None,
        }
    }

    /// Returns the boolean, if this value is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    /// True when this value is `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns a short description of the JSON type for diagnostics.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Int(_) => "integer",
            Self::Str(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::Str(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Self::Str(text)
    }
}

impl From<bool> for Value {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

impl From<i64> for Value {
    fn from(number: i64) -> Self {
        Self::Int(number)
    }
}

impl From<usize> for Value {
    fn from(number: usize) -> Self {
        Self::Int(i64::try_from(number).unwrap_or(i64::MAX))
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Self::Array(items)
    }
}

impl From<Object> for Value {
    fn from(object: Object) -> Self {
        Self::Object(object)
    }
}

impl<T> From<Option<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: Option<T>) -> Self {
        match value {
            Some(inner) => inner.into(),
            None => Self::Null,
        }
    }
}
