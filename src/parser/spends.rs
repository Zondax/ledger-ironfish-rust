#[cfg_attr(test, derive(Debug))]
#[derive(Copy, PartialEq)]
pub struct Spends<'a>(&'a [u8]);
