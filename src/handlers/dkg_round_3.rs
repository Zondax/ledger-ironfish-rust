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

use core::ptr::addr_of_mut;

use core::mem::MaybeUninit;

use crate::accumulator::accumulate_data;
use crate::buffer::Buffer;
use crate::context::TxContext;
use crate::error::ParserError;
use crate::handlers::dkg_get_identity::compute_dkg_secret;
use crate::parser::{parse_round, Deserializable, RawField};
use crate::utils::{canary, zlog_stack};
use crate::{AppSW, Instruction};
use alloc::vec::Vec;
use ironfish_frost::dkg;
use ironfish_frost::dkg::group_key::GroupSecretKey;
use ironfish_frost::dkg::round1::PublicPackage;
use ironfish_frost::dkg::round2::CombinedPublicPackage;
use ironfish_frost::dkg::round3::PublicKeyPackage;
use ironfish_frost::error::IronfishFrostError;
use ironfish_frost::frost::keys::KeyPackage;
use ironfish_frost::participant::Secret;
use ledger_device_sdk::io::{Comm, Event};

const MAX_APDU_SIZE: usize = 253;

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

#[inline(never)]
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

    let response = generate_response(&key_package, &public_key_package, &group_secret_key);

    drop(key_package);
    drop(public_key_package);

    send_apdu_chunks(comm, &response)
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

fn generate_response(
    _key_package: &KeyPackage,
    public_key_package: &PublicKeyPackage,
    _group_secret_key: &GroupSecretKey,
) -> Vec<u8> {
    let mut resp: Vec<u8> = Vec::new();
    let mut public_key_package_vec = public_key_package.serialize();
    let public_key_package_len = public_key_package_vec.len();

    resp.append(
        &mut [
            (public_key_package_len >> 8) as u8,
            (public_key_package_len & 0xFF) as u8,
        ]
        .to_vec(),
    );
    resp.append(&mut public_key_package_vec);

    resp
}

fn send_apdu_chunks(comm: &mut Comm, data_vec: &Vec<u8>) -> Result<(), AppSW> {
    let data = data_vec.as_slice();
    let total_chunks = (data.len() + MAX_APDU_SIZE - 1) / MAX_APDU_SIZE;

    for (i, chunk) in data.chunks(MAX_APDU_SIZE).enumerate() {
        comm.append(chunk);

        if i < total_chunks - 1 {
            comm.reply_ok();
            match comm.next_event() {
                Event::Command(Instruction::DkgRound2 { chunk: 0 }) => {}
                _ => {}
            }
        }
    }

    Ok(())
}
