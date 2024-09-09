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

use crate::{AppSW};
use core::ptr::addr_of_mut;

use core::mem::MaybeUninit;
use crate::deserialize::{Deserializable, RawField};
use crate::error::ParserError;
use alloc::vec::Vec;
use ironfish_frost::dkg;
use ironfish_frost::dkg::group_key::GroupSecretKey;
use ironfish_frost::dkg::round1::PublicPackage;
use ironfish_frost::dkg::round2::CombinedPublicPackage;
use ironfish_frost::dkg::round3::PublicKeyPackage;
use ironfish_frost::error::IronfishFrostError;
use ironfish_frost::frost::keys::KeyPackage;
use ironfish_frost::participant::Secret;
use ledger_device_sdk::io::{Comm};
use crate::accumulator::accumulate_data;
use crate::nvm::buffer::{Buffer};
use crate::context::TxContext;
use crate::handlers::dkg_get_identity::compute_dkg_secret;
use crate::nvm::dkg_keys::DkgKeys;
use crate::utils::{canary, zlog_stack};


pub struct Tx<'a> {
    identity_index: u8,
    round_1_public_packages: RawField<'a, PublicPackage>,
    round_2_public_packages: RawField<'a, CombinedPublicPackage>,
    round_2_secret_package: &'a [u8],
}

impl Deserializable for PublicPackage {
    #[inline(never)]
    fn from_bytes_into(
        input: &[u8],
        output: &mut MaybeUninit<PublicPackage>,
    ) -> Result<(), ParserError> {
        PublicPackage::deserialize_from_into(input, output)
            .map_err(|_| ParserError::InvalidPublicPackage)
    }
}

// CombinedPublicPackage is smaller, it only holds
// a vector, which is around 48 bytes
impl Deserializable for CombinedPublicPackage {
    #[inline(never)]
    fn from_bytes_into(
        input: &[u8],
        output: &mut MaybeUninit<CombinedPublicPackage>,
    ) -> Result<(), ParserError> {
        let p = CombinedPublicPackage::deserialize_from(input)
            .map_err(|_| ParserError::InvalidCombinedPackage)?;

        output.write(p);
        Ok(())
    }
}

pub fn handler_dkg_round_3(comm: &mut Comm, chunk: u8, ctx: &mut TxContext) -> Result<(), AppSW> {
    zlog_stack("start handler_dkg_round_3\0");

    accumulate_data(comm, chunk, ctx)?;
    if !ctx.done {
        return Ok(());
    }

    let mut tx = MaybeUninit::uninit();
    parse_tx_lazy(ctx.buffer_pos, &mut tx).map_err(|_| AppSW::TxParsingFail)?;
    let tx = unsafe { tx.assume_init() };

    // Reset transaction context as we want to release space on the heap
    ctx.reset();

    let dkg_secret = compute_dkg_secret(tx.identity_index);
    let (key_package, public_key_package, group_secret_key) =
        compute_dkg_round_3(&dkg_secret, tx).map_err(|_| AppSW::DkgRound3Fail)?;

    drop(dkg_secret);

    save_response(key_package, public_key_package, group_secret_key);

    Ok(())
}

#[inline(never)]
fn parse_round<T: Deserializable>(
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


#[inline(never)]
fn parse_tx_lazy(
    max_buffer_pos: usize,
    out: &mut MaybeUninit<Tx<'static>>,
) -> Result<(), ParserError> {
    zlog_stack("start parse_tx_lazy round3\0");

    let mut tx_pos: usize = 0;

    let identity_index = Buffer.get_element(tx_pos);
    tx_pos += 1;

    let mut num_elements = 0;
    let mut element_len = 0;

    let (round_1_public_packages, tx_pos) =
        parse_round::<PublicPackage>(tx_pos, &mut num_elements, &mut element_len)
            .map(|(round1, tx_pos)| (RawField::new(num_elements, element_len, round1), tx_pos))?;
    canary();

    let (round_2_public_packages, mut tx_pos) =
        parse_round::<CombinedPublicPackage>(tx_pos, &mut num_elements, &mut element_len)
            .map(|(round2, tx_pos)| (RawField::new(num_elements, element_len, round2), tx_pos))?;
    canary();

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos + 1) as u16))
        as usize;
    tx_pos += 2;

    let round_2_secret_package = Buffer.get_slice(tx_pos, tx_pos + len);
    tx_pos += len;

    if tx_pos != max_buffer_pos {
        return Err(ParserError::InvalidPayload);
    }

    let out = out.as_mut_ptr();
    unsafe {
        addr_of_mut!((*out).round_2_secret_package).write(round_2_secret_package);
        addr_of_mut!((*out).round_1_public_packages).write(round_1_public_packages);
        addr_of_mut!((*out).round_2_public_packages).write(round_2_public_packages);
        addr_of_mut!((*out).identity_index).write(identity_index);
    }

    Ok(())
}

#[inline(never)]
fn compute_dkg_round_3(
    secret: &Secret,
    tx: Tx,
) -> Result<(KeyPackage, PublicKeyPackage, GroupSecretKey), IronfishFrostError> {
    zlog_stack("compute_dkg_round_3\0");

    let round1_iter = tx.round_1_public_packages;
    let round2_iter = tx.round_2_public_packages;

    dkg::round3::round3(
        secret,
        tx.round_2_secret_package,
        &round1_iter,
        &round2_iter,
    )
}

#[inline(never)]
fn save_response(key_package: KeyPackage, public_key_package: PublicKeyPackage, group_secret_key: GroupSecretKey) {
    DkgKeys.set_u16(0, 6);
    let mut pos = DkgKeys.set_slice_with_len(6, key_package.serialize().unwrap().as_slice());
    DkgKeys.set_u16(2, pos as u16);
    pos = DkgKeys.set_slice_with_len(pos, group_secret_key.as_slice());
    DkgKeys.set_u16(4, pos as u16);
    pos = DkgKeys.set_slice_with_len(pos, public_key_package.serialize().as_slice());

    // TODO check that last pos is not bigger than dkg_keys buffer
}