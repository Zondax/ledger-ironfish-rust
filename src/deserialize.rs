use alloc::boxed::Box;
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

    fn from_bytes_into(input: &[u8], output: &mut Self) -> Result<(), ParserError> {
        *output = Self::from_bytes(input)?;

        Ok(())
    }

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
    current_element: Box<Option<T>>,
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

    #[inline(never)]
    pub fn iter(&'a self) -> RawFieldIterator<'a, T> {
        let current_element = Box::new(None);
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

    #[inline(never)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.elements_read >= self.field.num_elements {
            return None;
        }

        let end = self.current_position + self.field.len;
        let input = &self.field.raw[self.current_position..end];

        if self.current_element.is_none() {
            *self.current_element = Some(T::from_bytes(input).ok()?);
        } else {
            let ptr = &mut *self.current_element;
            T::from_bytes_into(input, ptr.as_mut().unwrap()).ok()?;
        }

        self.current_position = end;
        self.elements_read += 1;

        // SAFETY: This is safe because the reference is valid for the lifetime of self,
        // and we've just set current_element to Some(value)
        unsafe { Some(&*(self.current_element.as_ref().as_ref().unwrap() as *const T)) }
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

    #[inline(never)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T: Deserializable> Clone for RawFieldIterator<'a, T>
where
    T: Deserializable,
{
    #[inline(never)]
    fn clone(&self) -> Self {
        let current_element = Box::new(None);
        RawFieldIterator {
            field: self.field,
            current_position: self.current_position,
            elements_read: self.elements_read,
            current_element,
            _marker: PhantomData,
        }
    }
}
