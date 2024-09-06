use ledger_device_sdk::nvm::*;
use ledger_device_sdk::NVMData;

// This is necessary to store the object in NVM and not in RAM
pub const DKG_KEYS_MAX_SIZE: usize = 6000;
#[link_section = ".nvm_data"]
static mut DATA: NVMData<AlignedStorage<[u8; DKG_KEYS_MAX_SIZE]>> =
    NVMData::new(AlignedStorage::new([0u8; DKG_KEYS_MAX_SIZE]));

#[derive(Clone, Copy)]
pub struct DkgKeys;

impl Default for DkgKeys {
    fn default() -> Self {
        DkgKeys
    }
}

impl DkgKeys {
    #[inline(never)]
    #[allow(unused)]
    pub fn get_mut_ref(&mut self) -> &mut AlignedStorage<[u8; DKG_KEYS_MAX_SIZE]> {
        unsafe { DATA.get_mut() }
    }

    #[allow(unused)]
    pub fn get_element(&self, index: usize) -> u8 {
        let buffer = unsafe { DATA.get_mut() };
        buffer.get_ref()[index]
    }

    #[allow(unused)]
    pub fn set_element(&self, index: usize, value: u8) {
        let mut updated_data: [u8; DKG_KEYS_MAX_SIZE] = unsafe { *DATA.get_mut().get_ref() };
        updated_data[index] = value;
        unsafe {
            DATA.get_mut().update(&updated_data);
        }
    }

    #[allow(unused)]
    pub fn set_slice(&self, mut index: usize, value: &[u8]) {
        let mut updated_data: [u8; DKG_KEYS_MAX_SIZE] = unsafe { *DATA.get_mut().get_ref() };
        for b in value.iter() {
            updated_data[index] = *b;
            index += 1;
        }
        unsafe {
            DATA.get_mut().update(&updated_data);
        }
    }

    #[allow(unused)]
    pub fn set_slice_with_len(&self, mut index: usize, value: &[u8]) -> usize {
        let mut updated_data: [u8; DKG_KEYS_MAX_SIZE] = unsafe { *DATA.get_mut().get_ref() };
        let len = value.len();
        updated_data[index] = (len >> 8) as u8;
        index += 1;
        updated_data[index] = (len & 0xff) as u8;
        index += 1;

        for b in value.iter() {
            updated_data[index] = *b;
            index += 1;
        }
        unsafe {
            DATA.get_mut().update(&updated_data);
        }

        index
    }

    #[allow(unused)]
    pub fn get_slice(&self, start_pos: usize, end_pos:usize) -> &[u8] {
        let buffer = unsafe { DATA.get_mut() };
        &buffer.get_ref()[start_pos..end_pos]
    }

    #[allow(unused)]
    pub fn set_u16(&self, mut index: usize, value: u16) -> usize{
        let mut updated_data: [u8; DKG_KEYS_MAX_SIZE] = unsafe { *DATA.get_mut().get_ref() };
        updated_data[index] = (value >> 8) as u8;
        index += 1;
        updated_data[index] = (value & 0xff) as u8;
        index += 1;
        unsafe {
            DATA.get_mut().update(&updated_data);
        }
        index
    }

    #[allow(unused)]
    pub fn get_u16(&self, start_pos: usize) -> usize {
        let buffer = unsafe { DATA.get_mut() };
        (buffer.get_ref()[start_pos] << 8 | buffer.get_ref()[start_pos+1] ) as usize
    }
}
