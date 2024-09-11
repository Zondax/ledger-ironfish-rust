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
use ironfish_frost::frost::keys::KeyPackage;
use ironfish_frost::signing_commitment;
use ledger_device_sdk::io::{Comm, Event};
use serde::Serialize;
use crate::accumulator::accumulate_data;
use crate::nvm::buffer::{Buffer};
use crate::context::TxContext;
use crate::utils::{zlog_stack};
use ironfish_frost::nonces::deterministic_signing_nonces;
use ironfish_frost::frost::round1::SigningCommitments;
use ironfish_frost::participant::Identity;
use crate::nvm::dkg_keys::DkgKeys;

const MAX_APDU_SIZE: usize = 253;

#[inline(never)]
pub fn handler_dkg_commitment(
    comm: &mut Comm,
    chunk: u8,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    zlog_stack("start handler_commitment\0");

    accumulate_data(comm, chunk, ctx)?;
    if !ctx.done {
        return Ok(());
    }

    let (identities, tx_hash) = parse_tx(ctx.buffer_pos);
    let key_package = load_key_package();

    let nonces = deterministic_signing_nonces(
        key_package.signing_share(),
        tx_hash,
        &identities,
    );

    let signing_commitment:SigningCommitments  = (&nonces).into();
    let ser = signing_commitment.serialize().unwrap();

    send_apdu_chunks(comm, ser)
}


#[inline(never)]
fn load_key_package() -> KeyPackage{
    zlog_stack("start load_key_package\0");

    let start = DkgKeys.get_u16(0);
    let len = DkgKeys.get_u16(start);

    KeyPackage::deserialize(DkgKeys.get_slice(start+2, start+2+len)).unwrap()
}

#[inline(never)]
fn parse_tx(max_buffer_pos: usize) -> (Vec<Identity>, &'static [u8]){
    zlog_stack("start parse_tx\0");

    let mut tx_pos = 0;
    let elements = Buffer.get_element(tx_pos);
    tx_pos +=1;

    let mut identities:Vec<Identity> = Vec::new();
    for _i in 0..elements {
        let identity = Identity::deserialize_from(Buffer.get_slice(tx_pos,tx_pos+129)).unwrap();
        tx_pos += 129;

        identities.push(identity);
    }

    let tx_hash = Buffer.get_slice(tx_pos, max_buffer_pos);

    (identities, tx_hash)
}

#[inline(never)]
fn send_apdu_chunks(comm: &mut Comm, data_vec: Vec<u8>) -> Result<(), AppSW> {
    zlog_stack("start send_apdu_chunks\0");

    let data = data_vec.as_slice();
    let total_chunks = (data.len() + MAX_APDU_SIZE - 1) / MAX_APDU_SIZE;

    for (i, chunk) in data.chunks(MAX_APDU_SIZE).enumerate() {
        zlog_stack("iter send_apdu_chunks\0");
        comm.append(chunk);

        if i < total_chunks - 1 {
            zlog_stack("another send_apdu_chunks\0");
            comm.reply_ok();
            match comm.next_event() {
                Event::Command(Instruction::DkgRound2 { chunk: 0 }) => {}
                _ => {},
            }
        }
    }

    Ok(())
}
