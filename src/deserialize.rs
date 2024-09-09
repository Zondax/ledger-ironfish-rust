use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use crate::error::ParserError;
use crate::utils::zlog_stack;

/// The Deserializable trait defines a common interface for types that can be deserialized from a byte stream
/// This trait is used to provide a generic way of deserializing objects from any type that implements std::io::Read.
/// It's particularly useful for working with raw byte data, such as when reading from files,
/// network streams, or in-memory buffers.
pub trait Deserializable: Sized {
    fn from_bytes(input: &[u8]) -> Result<Self, ParserError> {
        let mut output = MaybeUninit::uninit();
        Self::from_bytes_into(input, &mut output)?;

        Ok(unsafe { output.assume_init() })
    }

    fn from_bytes_into(input: &[u8], output: &mut MaybeUninit<Self>) -> Result<(), ParserError>;

    fn from_bytes_check(input: &[u8]) -> Result<(), ParserError> {
        Self::from_bytes(input).map(|_| ())
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(any(feature = "derive-debug", test), derive(Debug))]
pub struct RawField<'a, T> {
    num_elements: u8,
    len: usize,
    raw: &'a [u8],
    _marker: PhantomData<T>,
}

pub struct RawFieldIterator<'a, T: Deserializable> {
    field: &'a RawField<'a, T>,
    current_position: usize,
    current_element: Box<MaybeUninit<T>>,
    is_initialized: bool,
}

impl<'a, T> RawField<'a, T>
where
    T: Deserializable,
{
    pub fn new(num_elements: u8, len: usize, raw: &'a [u8]) -> Self {
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
        RawFieldIterator::new(self)
    }
}

impl<'a, T: Deserializable> RawFieldIterator<'a, T> {
    pub fn new(field: &'a RawField<'a, T>) -> Self {
        let current_element = Box::new(MaybeUninit::uninit());

        RawFieldIterator {
            field,
            current_position: 0,
            current_element,
            is_initialized: false,
        }
    }
}

impl<'a, T: Deserializable> Drop for RawFieldIterator<'a, T> {
    fn drop(&mut self) {
        // Log the drop event

        unsafe {
            // Assuming we've added a field to track initialization
            if self.is_initialized {
                core::ptr::drop_in_place(self.current_element.as_mut_ptr());
            }
        }
    }
}

impl<'a, T: Deserializable> Iterator for RawFieldIterator<'a, T> {
    type Item = &'a T;

    #[inline(never)]
    fn next(&mut self) -> Option<Self::Item> {
        let elements_read = self.current_position / self.field.len;
        if elements_read >= self.field.num_elements as usize {
            return None;
        }
        // Drop the previous T if it was initialized
        // in order to avoid memory leaks!!!
        if self.is_initialized {
            zlog_stack("RawFieldIterator::dropping_previous\0");
            unsafe {
                core::ptr::drop_in_place(self.current_element.as_mut_ptr());
            }
            self.is_initialized = false;
        }

        let input = &self.field.raw[self.current_position..];

        let Some(_) = T::from_bytes_into(input, self.current_element.as_mut()).ok() else {
            self.is_initialized = false;
            return None;
        };
        self.is_initialized = true;

        self.current_position += self.field.len;

        // SAFETY: This is safe because the reference is valid for the lifetime of self,
        // and we've just set current_element to Some(value)
        unsafe { Some(&*(self.current_element.as_ref().assume_init_ref() as *const T)) }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let elements_read = self.current_position / self.field.len;
        let remaining = self.field.num_elements as usize - elements_read;
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
        RawFieldIterator::new(self.field)
    }
}
