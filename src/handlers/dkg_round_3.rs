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
use alloc::vec::Vec;
use ironfish_frost::dkg;
use ironfish_frost::dkg::group_key::GroupSecretKey;
use ironfish_frost::dkg::round1::PublicPackage;
use ironfish_frost::dkg::round2::CombinedPublicPackage;
use ironfish_frost::dkg::round3::PublicKeyPackage;
use ironfish_frost::error::IronfishFrostError;
use ironfish_frost::frost::keys::KeyPackage;
use ledger_device_sdk::io::{Comm};
use crate::accumulator::accumulate_data;
use crate::nvm::buffer::{Buffer};
use crate::context::TxContext;
use crate::handlers::dkg_get_identity::compute_dkg_secret;
use crate::nvm::dkg_keys::DkgKeys;
use crate::utils::{zlog_stack};


#[inline(never)]
pub fn handler_dkg_round_3(
    comm: &mut Comm,
    chunk: u8,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    zlog_stack("start handler_dkg_round_3\0");

    accumulate_data(comm, chunk, ctx)?;
    if !ctx.done {
        return Ok(());
    }

    // Try to deserialize the transaction
    let (round_1_public_packages, round_2_public_packages, round_2_secret_package) = parse_tx();
    // Reset transaction context as we want to release space on the heap
    ctx.reset();

    let (key_package, public_key_package, group_secret_key)
        = compute_dkg_round_3(round_1_public_packages, round_2_public_packages, round_2_secret_package).map_err(|_| AppSW::DkgRound3Fail)?;

    save_response(key_package, public_key_package, group_secret_key);

    Ok(())
}

#[inline(never)]
fn parse_round_1_public_packages(mut tx_pos: usize) -> (Vec<PublicPackage>, usize){
    zlog_stack("start parse_round_1_public_packages\0");
    let elements = Buffer.get_element(tx_pos);
    tx_pos +=1;

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos+1) as u16)) as usize;
    tx_pos +=2;

    let mut round_1_public_packages : Vec<PublicPackage> = Vec::with_capacity(elements as usize);
    for _i in 0..elements {
        zlog_stack("start parse_round_1 - e\0");
        let public_package = PublicPackage::deserialize_from(Buffer.get_slice(tx_pos,tx_pos+len)).unwrap();
        tx_pos += len;

        zlog_stack("push parse_round_1 - e\0");
        round_1_public_packages.push(public_package);
        zlog_stack("done parse_round_1 - e\0");
    }

    zlog_stack("done parse_round_1_public_packages\0");
    (round_1_public_packages, tx_pos)
}

#[inline(never)]
fn parse_round_2_public_packages(mut tx_pos: usize)-> (Vec<CombinedPublicPackage>, usize){
    zlog_stack("start parse_round_2_public_packages\0");
    let elements = Buffer.get_element(tx_pos);
    tx_pos +=1;

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos+1) as u16)) as usize;
    tx_pos +=2;

    let mut round_2_public_packages : Vec<CombinedPublicPackage> = Vec::with_capacity(elements as usize);
    for _i in 0..elements {
        zlog_stack("start parse_round_2 - e\0");
        let c_public_package = CombinedPublicPackage::deserialize_from(Buffer.get_slice(tx_pos,tx_pos+len)).unwrap();
        tx_pos += len;

        zlog_stack("push parse_round_2 - e\0");
        round_2_public_packages.push(c_public_package);
        zlog_stack("done parse_round_2 - e\0");
    }

    zlog_stack("done parse_round_1_public_packages\0");

    (round_2_public_packages, tx_pos)
}


#[inline(never)]
fn parse_tx() -> (Vec<PublicPackage>, Vec<CombinedPublicPackage>, &'static [u8]){
    zlog_stack("start parse_tx round3\0");

    let tx_pos:usize = 1;

    let (round_1_public_packages, tx_pos) = parse_round_1_public_packages(tx_pos);
    let (round_2_public_packages, mut tx_pos) = parse_round_2_public_packages(tx_pos);

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos+1) as u16)) as usize;
    tx_pos +=2;

    let round_2_secret_package = Buffer.get_slice(tx_pos,tx_pos+len);


    zlog_stack("done parse_tx round3\0");

    (round_1_public_packages, round_2_public_packages, round_2_secret_package)
}

#[inline(never)]
fn compute_dkg_round_3(round_1_public_packages: Vec<PublicPackage>, round_2_public_packages: Vec<CombinedPublicPackage>, round_2_secret_package: &[u8]) -> Result<(KeyPackage, PublicKeyPackage, GroupSecretKey), IronfishFrostError> {
    zlog_stack("start compute_dkg_round_3\0");

    let secret = compute_dkg_secret(Buffer.get_element(0));

   dkg::round3::round3(
        &secret,
        round_2_secret_package,
        &round_1_public_packages,
        &round_2_public_packages
    )
}

#[inline(never)]
fn save_response(key_package: KeyPackage, public_key_package: PublicKeyPackage, group_secret_key: GroupSecretKey) {
    DkgKeys.set_u16(0, 6);
    let mut pos = DkgKeys.set_slice_with_len(6, key_package.serialize().unwrap().as_slice());
    DkgKeys.set_u16(2, pos as u16);
    let mut pos = DkgKeys.set_slice_with_len(pos, group_secret_key.as_slice());
    DkgKeys.set_u16(4, pos as u16);
    let mut _pos = DkgKeys.set_slice_with_len(pos, public_key_package.serialize().as_slice());
}