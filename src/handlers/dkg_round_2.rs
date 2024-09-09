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
use ledger_device_sdk::random::LedgerRng;
use ironfish_frost::dkg;
use ironfish_frost::dkg::round1::PublicPackage;
use ironfish_frost::dkg::round2::CombinedPublicPackage;
use ironfish_frost::error::IronfishFrostError;
use ledger_device_sdk::io::{Comm, Event};
use crate::accumulator::accumulate_data;
use crate::nvm::buffer::{Buffer};
use crate::handlers::dkg_get_identity::compute_dkg_secret;
use crate::context::TxContext;
use crate::utils::{zlog_stack};

const MAX_APDU_SIZE: usize = 253;

#[inline(never)]
pub fn handler_dkg_round_2(
    comm: &mut Comm,
    chunk: u8,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    zlog_stack("start handler_dkg_round_2\0");

    accumulate_data(comm, chunk, ctx)?;
    if !ctx.done {
        return Ok(());
    }

    let (round_1_public_packages, tx_pos) = parse_round_1_public_packages();
    let round_1_secret_package = parse_round_1_secret_package(tx_pos);

    // Reset transaction context as we want to release space on the heap
    ctx.reset();

    let (mut round2_secret_package_vec, round2_public_package) = compute_dkg_round_2(round_1_public_packages, round_1_secret_package).map_err(|_| AppSW::DkgRound2Fail)?;

    let response = generate_response(&mut round2_secret_package_vec, &round2_public_package);
    drop(round2_secret_package_vec);
    drop(round2_public_package);

    send_apdu_chunks(comm, &response)
}

#[inline(never)]
fn parse_round_1_public_packages() -> (Vec<PublicPackage>, usize){
    zlog_stack("start parse_tx round2\0");

    let mut tx_pos:usize = 1;

    let elements = Buffer.get_element(tx_pos);
    tx_pos +=1;

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos+1) as u16)) as usize;
    tx_pos +=2;

    let mut round_1_public_packages : Vec<PublicPackage> = Vec::new();
    for _i in 0..elements {
        let public_package = PublicPackage::deserialize_from(Buffer.get_slice(tx_pos,tx_pos+len)).unwrap();
        tx_pos += len;

        round_1_public_packages.push(public_package);
    }

    (round_1_public_packages, tx_pos)
}
#[inline(never)]
fn parse_round_1_secret_package(mut tx_pos:usize) -> &'static [u8] {
    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos+1) as u16)) as usize;
    tx_pos +=2;

    Buffer.get_slice(tx_pos,tx_pos+len)
}

#[inline(never)]
fn compute_dkg_round_2(round_1_public_packages:Vec<PublicPackage>, round_1_secret_package: &[u8]) -> Result<(Vec<u8>, CombinedPublicPackage), IronfishFrostError> {
    zlog_stack("start compute_dkg_round_2\0");

    let mut rng = LedgerRng{};
    let secret = compute_dkg_secret(Buffer.get_element(0));

   dkg::round2::round2(
        &secret,
        round_1_secret_package,
        &round_1_public_packages,
        &mut rng,
    )
}

#[inline(never)]
fn generate_response(mut round2_secret_package_vec: &mut Vec<u8>, round2_public_package: &CombinedPublicPackage) -> Vec<u8> {
    let mut resp : Vec<u8> = Vec::new();
    let mut round2_public_package_vec = round2_public_package.serialize();
    let round2_public_package_len = round2_public_package_vec.len();
    let round2_secret_package_len = round2_secret_package_vec.len();

    resp.append(&mut [(round2_secret_package_len >> 8) as u8, (round2_secret_package_len & 0xFF) as u8].to_vec());
    resp.append(&mut round2_secret_package_vec);
    resp.append(&mut [(round2_public_package_len >> 8) as u8, (round2_public_package_len & 0xFF) as u8].to_vec());
    resp.append(&mut round2_public_package_vec);

    resp
}

#[inline(never)]
fn send_apdu_chunks(comm: &mut Comm, data_vec: &Vec<u8>) -> Result<(), AppSW> {
    let data = data_vec.as_slice();
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
