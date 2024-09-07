use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::error::ParserError;
use crate::utils::zlog_stack;

/// The Deserializable trait defines a common interface for types that can be deserialized from a byte stream
/// This trait is used to provide a generic way of deserializing objects from any type that implements std::io::Read.
/// It's particularly useful for working with raw byte data, such as when reading from files,
/// network streams, or in-memory buffers.
pub trait Deserializable: Sized {
    fn from_bytes(input: &[u8]) -> Result<Self, ParserError>;

    fn from_bytes_check(input: &[u8]) -> Result<(), ParserError> {
        Self::from_bytes(input).map(|_| ())
    }
}

#[derive(Clone, Copy)]
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
    current_element: Vec<Option<T>>,
    _marker: PhantomData<&'a T>,
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

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn iter(&'a self) -> RawFieldIterator<'a, T> {
        let current_element = vec![None];
        RawFieldIterator {
            field: self,
            current_position: 0,
            elements_read: 0,
            current_element,
            _marker: PhantomData,
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
        let value = T::from_bytes(&self.field.raw[self.current_position..end]).ok()?;
        self.current_element[0] = Some(value);

        self.current_position = end;
        self.elements_read += 1;

        // SAFETY: This is safe because the reference is valid for the lifetime of self,
        // and we've just set current_element to Some(value)
        unsafe { Some(&*(self.current_element[0].as_ref().unwrap() as *const T)) }
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

impl<'a, T: Deserializable> Clone for RawFieldIterator<'a, T>
where
    T: Deserializable,
{
    fn clone(&self) -> Self {
        let current_element = vec![None];
        RawFieldIterator {
            field: self.field,
            current_position: self.current_position,
            elements_read: self.elements_read,
            current_element,
            _marker: PhantomData,
        }
    }
}
