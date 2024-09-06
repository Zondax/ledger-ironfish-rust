use crate::AppSW;

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ParserError {
    Ok,
    InvalidPublicPackage,
    InvalidCombinedPackage,
    InvalidPayload,
    //... more error definitions
}

impl From<ParserError> for AppSW {
    fn from(err: ParserError) -> Self {
        match err {
            ParserError::Ok => AppSW::Ok,
            ParserError::InvalidPublicPackage => AppSW::TxParsingFail,
            ParserError::InvalidCombinedPackage => AppSW::TxParsingFail,
            _ => AppSW::TxParsingFail, //... more error mappings
        }
    }
}
