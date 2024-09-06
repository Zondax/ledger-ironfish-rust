use core::marker::PhantomData;
use ouroboros::self_referencing;

use crate::error::ParserError;

/// The Deserializable trait defines a common interface for types that can be deserialized from a byte stream
/// This trait is used to provide a generic way of deserializing objects from any type that implements std::io::Read.
/// It's particularly useful for working with raw byte data, such as when reading from files,
/// network streams, or in-memory buffers.
pub trait Deserializable: Sized {
    fn from_bytes(input: &[u8]) -> Result<Self, ParserError>;
}
#[derive(Clone)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct RawField<'a, T> {
    num_elements: usize,
    len: usize,
    raw: &'a [u8],
    _marker: PhantomData<T>,
}

pub struct RawFieldIterator<'a, T: Deserializable> {
    field: &'a RawField<'a, T>,
    current_position: usize,
    elements_read: usize,
    current_element: Option<T>
}

impl<'a, T> RawField<'a, T>
where
    T: Deserializable,
{
    pub fn new(num_elements: usize, len: usize, raw: &'a [u8]) -> Self {
        RawField {
            num_elements,
            len,
            raw,
            _marker: PhantomData,
        }
    }

    pub fn iter(&self) -> RawFieldIterator<'a, T> {
        RawFieldIterator {
            field: self,
            current_position: 0,
            elements_read: 0,
           current_element: None,
        }
    }
}

impl<'a, T: Deserializable> Iterator for RawFieldIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.elements_read >= self.field.num_elements {
            return None;
        }

        let end = self.current_position + self.field.len;
        let value = T::from_bytes(&self.field.raw[self.current_position..end])
            .expect("Failed to deserialize");
        self.current_element.replace(value);

        self.current_position = end;
        self.elements_read += 1;

        self.current_element.as_ref()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.field.num_elements - self.elements_read;
        (remaining, Some(remaining))
    }
}

impl<'a, T: Deserializable> ExactSizeIterator for RawFieldIterator<'a, T> {}

impl<'a, T: Deserializable> IntoIterator for &'a RawField<'a, T> {
    type Item = &'a T;
    type IntoIter = RawFieldIterator<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T: Deserializable> Clone for RawFieldIterator<'a, T> {
    fn clone(&self) -> Self {
        RawFieldIterator {
            field: self.field,
            current_position: self.current_position,
            elements_read: self.elements_read,
            current_element: None,
        }
    }
}
