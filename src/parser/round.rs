use crate::{
    buffer::Buffer,
    error::ParserError,
    utils::{canary, zlog_stack},
};

use super::Deserializable;

/// Reads from internal buffer, returning the raw bytes
/// that represent a list of elements of type T,
/// writing in num_elements the number of elements, and
/// the len of bytes necessary to parse each one.
/// It also returns the index pointing to the next byte after the
/// list

/// Parses a list of elements of type `T` from the internal buffer starting at the given `tx_pos`.
///
/// # Arguments
///
/// * `tx_pos` - The starting position in the buffer to begin parsing.
/// * `num_elements` - A mutable reference where the number of parsed elements will be stored.
/// * `element_len` - A mutable reference where the length in bytes of each element will be stored.
///
/// # Returns
///
/// Returns a tuple containing:
/// * A slice of the raw bytes that represent the parsed elements.
/// * The updated index pointing to the next byte after the parsed list.
///
/// # Errors
///
/// Returns a `ParserError` if an element fails to be parsed or deserialized.
///
/// # Function Behavior
///
/// - Reads the number of elements from the buffer and updates `tx_pos`.
/// - Reads the length of each element (in bytes) from the buffer and updates `tx_pos`.
/// - Iterates over each element, checking its validity using the `T::from_bytes_check` method.
/// - Updates the `num_elements` and `element_len` references with the parsed data.
/// - Returns a slice of the parsed elements and the updated position.
/// - Logs the start and end of the parsing process.
#[inline(never)]
pub fn parse_round<T: Deserializable>(
    mut tx_pos: usize,
    num_elements: &mut u8,
    element_len: &mut usize,
) -> Result<(&'static [u8], usize), ParserError> {
    zlog_stack("parse_round\0");
    let elements = Buffer.get_element(tx_pos);
    tx_pos += 1;

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos + 1) as u16))
        as usize;
    tx_pos += 2;

    let start = tx_pos;
    for _ in 0..elements {
        canary();
        T::from_bytes_check(Buffer.get_slice(start, tx_pos + len))?;
        tx_pos += len;
    }

    *num_elements = elements;
    *element_len = len;

    let slice = Buffer.get_slice(start, tx_pos);
    zlog_stack("done parse_round\0");

    Ok((slice, tx_pos))
}
