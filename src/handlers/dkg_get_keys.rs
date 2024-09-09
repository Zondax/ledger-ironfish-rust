/*****************************************************************************
 *   Ledger App Ironfish Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

use crate::{AppSW, Instruction};
use alloc::vec::Vec;
use ironfish_frost::dkg::group_key::{GroupSecretKey, GROUP_SECRET_KEY_LEN};
use ironfish_frost::dkg::round3::PublicKeyPackage;
use ledger_device_sdk::io::{Comm, Event};
use crate::ironfish::multisig::derive_account_keys;
use crate::utils::{zlog_stack};
use crate::nvm::dkg_keys::DkgKeys;

const MAX_APDU_SIZE: usize = 253;

#[inline(never)]
pub fn handler_dkg_get_keys(
    comm: &mut Comm
) -> Result<(), AppSW> {
    zlog_stack("start handler_dkg_get_keys\0");

    let group_secret_key = load_group_secret_key();
    let public_key_package = load_public_key_package();

    let verifying_key_vec = public_key_package.verifying_key().serialize().unwrap();
    let verifying_key = <&[u8; 32]>::try_from(verifying_key_vec.as_slice()).unwrap();

    let account_keys = derive_account_keys(verifying_key, &group_secret_key);

    let resp = account_keys.public_address.public_address();

    send_apdu_chunks(comm, &resp)
}


#[inline(never)]
fn load_group_secret_key() -> &'static GroupSecretKey{
    zlog_stack("start load_group_secret_key\0");

    let start = DkgKeys.get_u16(2);
    let len = DkgKeys.get_u16(start);

    let raw = DkgKeys.get_slice(start+2, start+2+len);
    <&[u8; GROUP_SECRET_KEY_LEN]>::try_from(raw).unwrap()
}

#[inline(never)]
fn load_public_key_package() -> PublicKeyPackage{
    zlog_stack("start load_public_key_package\0");

    let start = DkgKeys.get_u16(4);
    let len = DkgKeys.get_u16(start);

    PublicKeyPackage::deserialize_from(DkgKeys.get_slice(start+2, start+2+len)).unwrap()
}

#[inline(never)]
fn send_apdu_chunks(comm: &mut Comm, data: &[u8]) -> Result<(), AppSW> {
    zlog_stack("start send_apdu_chunks\0");

    let total_chunks = (data.len() + MAX_APDU_SIZE - 1) / MAX_APDU_SIZE;

    for (i, chunk) in data.chunks(MAX_APDU_SIZE).enumerate() {
        comm.append(chunk);

        if i < total_chunks - 1 {
            comm.reply_ok();
            match comm.next_event() {
                Event::Command(Instruction::DkgRound2 { chunk: 0 }) => {}
                _ => {},
            }
        }
    }

    Ok(())
}
