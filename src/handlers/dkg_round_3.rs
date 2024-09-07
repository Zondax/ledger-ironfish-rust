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
use crate::buffer::{Buffer, BUFFER_SIZE};
use crate::context::TxContext;
use crate::deserialize::{Deserializable, RawField};
use crate::error::ParserError;
use crate::handlers::dkg_get_identity::compute_dkg_secret;
use crate::utils::{zlog, zlog_stack};
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
    round_2_secret_package: Vec<u8>,
}

impl Deserializable for PublicPackage {
    #[inline(never)]
    fn from_bytes(input: &[u8]) -> Result<Self, ParserError> {
        zlog_stack("*before_des\0");

        let p = PublicPackage::deserialize_from(input).map_err(|_| {
            zlog_stack("des_error!!!\0");
            ParserError::InvalidPublicPackage
        })?;
        zlog_stack("*after_des\0");
        Ok(p)
    }
}

impl Deserializable for CombinedPublicPackage {
    #[inline(never)]
    fn from_bytes(input: &[u8]) -> Result<Self, ParserError> {
        zlog_stack("before_des\0");
        let c = CombinedPublicPackage::deserialize_from(input)
            .map_err(|_| ParserError::InvalidPublicPackage)?;
        zlog_stack("after_des\0");
        Ok(c)
    }
}

pub fn handler_dkg_round_3(comm: &mut Comm, chunk: u8, ctx: &mut TxContext) -> Result<(), AppSW> {
    zlog_stack("start handler_dkg_round_3\0");

    accumulate_data(comm, chunk, ctx)?;
    if !ctx.done {
        return Ok(());
    }

    // Try to deserialize the transaction
    // let tx: Tx = parse_tx_lazy(ctx.buffer_pos).map_err(|_| AppSW::TxParsingFail)?;
    // zlog_stack("tx_parsed!\0");
    let mut tx = MaybeUninit::uninit();
    parse_tx_lazy(ctx.buffer_pos, &mut tx).map_err(|_| AppSW::TxParsingFail)?;
    let tx = unsafe { tx.assume_init() };

    // Reset transaction context as we want to release space on the heap
    ctx.reset();

    let dkg_secret = compute_dkg_secret(tx.identity_index);
    let (key_package, public_key_package, group_secret_key) =
        compute_dkg_round_3(&dkg_secret, &tx).map_err(|_| AppSW::DkgRound3Fail)?;

    drop(tx);
    drop(dkg_secret);

    let response = generate_response(&key_package, &public_key_package, &group_secret_key);

    drop(key_package);
    drop(public_key_package);

    send_apdu_chunks(comm, &response)
}

#[inline(never)]
fn parse_round<T: Deserializable>(
    mut tx_pos: usize,
    num_elements: &mut usize,
    element_len: &mut usize,
) -> Result<(&'static [u8], usize), ParserError> {
    zlog_stack("[[[start parse_round\0");
    let elements = Buffer.get_element(tx_pos);
    tx_pos += 1;

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos + 1) as u16))
        as usize;
    tx_pos += 2;

    let start = tx_pos;
    for _ in 0..elements {
        T::from_bytes_check(Buffer.get_slice(start, tx_pos + len))?;
        tx_pos += len;
    }

    *num_elements = elements as usize;
    *element_len = len;

    zlog_stack("done parse_round]]]\0");
    let slice = Buffer.get_slice(start, tx_pos);

    Ok((slice, tx_pos))
}

#[inline(never)]
// fn parse_tx_lazy(max_buffer_pos: usize) -> Result<Tx<'static>, ParserError> {
fn parse_tx_lazy(max_buffer_pos: usize, out: &mut MaybeUninit<Tx<'static>>) -> Result<(), ParserError> {
    zlog_stack("start parse_tx_lazy round3\0");

    let mut tx_pos: usize = 0;

    let identity_index = Buffer.get_element(tx_pos);
    tx_pos += 1;

    let mut num_elements = 0;
    let mut element_len = 0;

    let (round_1_public_packages, tx_pos) =
        parse_round::<PublicPackage>(tx_pos, &mut num_elements, &mut element_len)?;

    let round_1_public_packages = RawField::new(num_elements, element_len, round_1_public_packages);
    zlog_stack("round1_packages_parsed\0");

    num_elements = 0;
    element_len = 0;

    let (round_2_public_packages, mut tx_pos) =
        parse_round::<CombinedPublicPackage>(tx_pos, &mut num_elements, &mut element_len)?;
    let round_2_public_packages = RawField::new(num_elements, element_len, round_2_public_packages);
    zlog_stack("round2_packages_parsed\0");

    let len = (((Buffer.get_element(tx_pos) as u16) << 8) | (Buffer.get_element(tx_pos + 1) as u16))
        as usize;
    tx_pos += 2;

    let round_2_secret_package = Buffer.get_slice(tx_pos, tx_pos + len).to_vec();
    tx_pos += len;

    if tx_pos != max_buffer_pos {
        return Err(ParserError::InvalidPayload);
    }

    // zlog_stack("Check iterator\0");
    // for _ in round_1_public_packages.iter() {
    //     zlog_stack("parsed\0");
    // }

    zlog_stack("***done parse_tx round3\0");

    // Ok(Tx {
    //     round_2_secret_package,
    //     round_1_public_packages,
    //     round_2_public_packages,
    //     identity_index,
    // })
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
    tx: &Tx,
) -> Result<(KeyPackage, PublicKeyPackage, GroupSecretKey), IronfishFrostError> {
    zlog_stack("compute_dkg_round_3\0");

    dkg::round3::round3(
        secret,
        &tx.round_2_secret_package,
        &tx.round_1_public_packages,
        &tx.round_2_public_packages,
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

// #[cfg(test)]
// mod round3_test {
//     use super::*;
//     use crate::buffer::{Buffer, BUFFER_SIZE};
//
//     extern crate std;
//
//     const BLOB: &str = "000301d072510338227d8ee51fa11e048b56ae479a655c5510b906b90d029112a11566bac776c69d4bcd6471ce832100f6dd9a4024bd9580b5cfea11
// b2c8cdb2be16a46a2117f1d22a47c4ab0804c21ce4d7b33b4527c861edf4fd588fff6d9e31ca08ebdd8abd4bf237e158c43df6f998b6f1421fd59b390522b2ecd
// 3ae0d40c18e5fa3048700000000c3d2051e028dc4fbf2e53b209422e7b088cb30caff3bad6574a6f0c8ee4b01e8c7b47cae421ca42072492cc7b80936acac113f
// d638f357317f6beaf1974ee946824d7fe10b408c07e21a4a85d064fa72ab09c154db9bdad9422a66d345e600902692d5ed9673618309d1cad554a47ef35ca4693
// 09b0c1ebe71d6b98f5481f15ae7ed6f907a0cb8000000de25e6e29446b1c30ea721dbc21b8fdcd80872db0d38362f4513da982738f17b8837b107f58280988c9e
// 0775bcf69da30300000020000000f7864b28ab538412d6d2ef7071051309b63e90949462544c21b64ce3a9b5d467ebda9fb96f01b180fb352f4945772a92c6ff7
// 4b60aecdea5b67312963b823979332fde4553bcea5fba26e70ee28167ff6c9c873e6d340feaa12823e1294c1c16f2c1152df538d41e3547a0e77c9e2328032ae6
// 2b139f1336a66f5506ddf8acc297b4497366d1e9a47232e78e0380a8104680ad7d2a9fc746464ee15ce5288ddef7d3fcd594fe400dfd4593b85e8307ad0b5a33a
// e3091985a74efda2e5b583f667f806232588ab7824cd7d2e031ca875b1fedf13e8dcd571ba5101e91173c36bbb7c67dba9c900d03e7a3728d4b182cce18f43cc5
// f36fdc3738cad1e641566d977e025dcef25e12900d8700000000c3d2051e02289e61a4985afcf93e2227195bbcabf2563dbc11f58e0a8854b0bcfe4ccbddca3d2
// fa9df85674fefe611f22a27121c74a6f5c26ebb0b681b8284062341e3e6e440825393e068ea9b5053abf299bfb5c0ab41801c696907440b6841922d698a0b853f
// 16fc92d8ceff2003792b4d19e0e1288799dc4262650956da74104065bab10bb80000001a88ae34247eddbc29294af8c932ac2df371bbbadd88a33d3a9da8fa6cc
// 50a090c493532962a6c12b1592d4091c8a9980300000020000000ff842f904ca9a480f0e2a393e45891cba1cc60d44368cd4c04ebe26aaef952e2205f2b798adf
// 4cb75917313886bf23104c1db36c7c77f73828e2850908ae8dde51d986c20352b90e5eb6ec6347d3902fd6c36d4a1979d956abf0d6980200035984cae8d3bd39e
// ac3b8f55faa1ee01c0a842b7814e2acbaa37236352225269be597b4497366d1e9a472b1d21580d6905b99af410bb19197bcbbb1f64c663381534de0e4ec969bad
// 4a38779b7f70f21ba296a4a8a47a98bb704666cb1ee5030a501ec42206a45ecaf062e0b6e85ca7b78577b92d89069cd01e97e1f7f1e2674b6adcd8b2bab618a22
// 1c8ee5ce37c9cca2ad9ff541f3dfd935d81bdf669cb4a4cac5fd7dba05aabcd78018700000000c3d2051e0295f0107a01e8fc93a5b3b541a884fba64bcd2f438b
// fd0710a061b76b3df52528a59856e40e9775a9d391c587104130c896182a008bdf985f570612759f4aff60401303081acdd8f444e162c63dcb0e896d2b88b2655
// c5748a17d660177b90ee94d16e07794501ebbbd161099ebd9964675b94f041d2487f9571d3032d883ec620ab8000000211b437354c57be697e32415f7efe01008
// 0af2b6a9fbb3d937dd7ee634f95b3be35f4c7d9d2eef23803c7a6648258ff60300000020000000a79072a60f255e4967f2197b501cf7649183faa11a11bbaf9dc
// 39680724c1ffd00d7a1460c532a17ffda2c48f4564ebe0863c295c1e7ac0cffe59c5616e54aa095322791cfc3b3bcd6b156093630e98d1434d2962f827187392a
// 430789b44eb501ac31cddb5fc3f40322452e0c96bc851cc13fd2822e9886a178049d0000819297b4497366d1e9a40201e97232e78e0380a8104680ad7d2a9fc74
// 6464ee15ce5288ddef7d3fcd594fe400dfd4593b85e8307ad0b5a33ae3091985a74efda2e5b583f667f806232588ab7824cd7d2e031ca875b1fedf13e8dcd571b
// a5101e91173c36bbb7c67dba9c900d03e7a3728d4b182cce18f43cc5f36fdc3738cad1e641566d977e025dcef25e12900d0200000072b1d21580d6905b99af410
// bb19197bcbbb1f64c663381534de0e4ec969bad4a38779b7f70f21ba296a4a8a47a98bb704666cb1ee5030a501ec42206a45ecaf062e0b6e85ca7b78577b92d89
// 069cd01e97e1f7f1e2674b6adcd8b2bab618a221c8ee5ce37c9cca2ad9ff541f3dfd935d81bdf669cb4a4cac5fd7dba05aabcd78012500000000c3d2051e980d2
// 498a7f1c5c48ae0a54e79f57edad728e35de860a841c6a6bfdff86bc100b393f7830bafa43772510338227d8ee51fa11e048b56ae479a655c5510b906b90d0291
// 12a11566bac776c69d4bcd6471ce832100f6dd9a4024bd9580b5cfea11b2c8cdb2be16a46a2117f1d22a47c4ab0804c21ce4d7b33b4527c861edf4fd588fff6d9
// e31ca08ebdd8abd4bf237e158c43df6f998b6f1421fd59b390522b2ecd3ae0d40c18e5fa3042500000000c3d2051e80c0ef9b6f952253d8da71c6c9ef96c1aed4
// dec17f3a511fdd23dcf28e24f607b393f7830bafa43772b1d21580d6905b99af410bb19197bcbbb1f64c663381534de0e4ec969bad4a38779b7f70f21ba296a4a
// 8a47a98bb704666cb1ee5030a501ec42206a45ecaf062e0b6e85ca7b78577b92d89069cd01e97e1f7f1e2674b6adcd8b2bab618a221c8ee5ce37c9cca2ad9ff54
// 1f3dfd935d81bdf669cb4a4cac5fd7dba05aabcd7801020000007232e78e0380a8104680ad7d2a9fc746464ee15ce5288ddef7d3fcd594fe400dfd4593b85e830
// 7ad0b5a33ae3091985a74efda2e5b583f667f806232588ab7824cd7d2e031ca875b1fedf13e8dcd571ba5101e91173c36bbb7c67dba9c900d03e7a3728d4b182c
// ce18f43cc5f36fdc3738cad1e641566d977e025dcef25e12900d2500000000c3d2051e7927faa7cafa24b359a71202c33f6b394d55b5755116c5127305eaa93aa
// 48608b393f7830bafa43772510338227d8ee51fa11e048b56ae479a655c5510b906b90d029112a11566bac776c69d4bcd6471ce832100f6dd9a4024bd9580b5cf
// ea11b2c8cdb2be16a46a2117f1d22a47c4ab0804c21ce4d7b33b4527c861edf4fd588fff6d9e31ca08ebdd8abd4bf237e158c43df6f998b6f1421fd59b390522b
// 2ecd3ae0d40c18e5fa3042500000000c3d2051e0beb96ccbbf98ff99577cb0e415272146b3e39a557f476df63d7505eda76bd04b393f7830bafa43700e0402523
// 8660943c6187cc0fe96f6fdcd576bbbdde85fefd88b0d00dce7ec4b57940f25b8257aa1610ae8e96fd6b5057590100000088000000fbe89a788a4a1696fa1f988
// b2403162f4f627978d30b66125e8502442b4b2aaf20578088361b36f4706044c464fdfcdfdabbdb7d690afb3a661ca50cfc9d1e595733604996afe4851820b731
// 69875c29001a97d54238621708cc9510efe26dd4a1ea815f12c50fd5f083a793391bdf0981a5a8b1eb70fa6420680730adbf4a86956204c37838200775981dee6
// 71eda9cfe40585bfc7c507a9658cd3221383c5c8e63c02338cde3a1";
//
//     #[test]
//     fn check_round3() {
//         let data = hex::decode(BLOB).unwrap();
//
//         Buffer.set_slice(0, &data);
//
//         // Try to deserialize the transaction
//         let tx: Tx = parse_tx_lazy(0).unwrap();
//
//         let dkg_secret = compute_dkg_secret(tx.identity_index);
//         let (key_package, public_key_package, group_secret_key) =
//             compute_dkg_round_3(&dkg_secret, &tx).unwrap();
//
//         // std::println!("{:?}", key_package);
//     }
// }
