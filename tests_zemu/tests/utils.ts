import {Asset, LATEST_TRANSACTION_VERSION, Note, Transaction, makeTestWitness} from '@ironfish/rust-nodejs'

// Taken from the rust code example
const NATIVE_ASSET = Buffer.from([81, 243, 58, 47, 20, 249, 39, 53, 229, 98, 220, 101, 138, 86, 57, 39, 157, 220, 163, 213, 7,
    154, 109, 18, 66, 178, 165, 136, 169, 203, 244, 76,
]);

export const buildTx = (publicAddress: string, viewKeys: any, proofKey: any) => {
    // create raw/proposed transaction
    let in_note = new Note(publicAddress, BigInt(42), Buffer.from(""), NATIVE_ASSET, publicAddress);
    let out_note = new Note(publicAddress, BigInt(40), Buffer.from(""), NATIVE_ASSET, publicAddress);
    let asset = new Asset(publicAddress, "Testcoin", "A really cool coin")
    
    let value = BigInt(5);
    let mint_out_note = new Note(publicAddress, value, Buffer.from(""), asset.id(), publicAddress);

    let witness = makeTestWitness(in_note);

    let transaction = new Transaction(LATEST_TRANSACTION_VERSION);
    transaction.spend(in_note, witness)
    transaction.output(out_note)
    transaction.mint(asset, value)
    transaction.output(mint_out_note)

    let intended_fee = BigInt(1);

    return transaction.build(
        proofKey.nsk,
        viewKeys.viewKey,
        viewKeys.ovk,
        intended_fee,
        publicAddress
    );
}