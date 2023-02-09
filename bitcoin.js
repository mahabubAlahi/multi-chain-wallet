var Bitcoin = require('bitcoinjs-lib');
var BIP39 = require('bip39');
const { hdkey } = require('ethereumjs-wallet')
const { HDKey } = require("ethereum-cryptography/hdkey");
var bitcore = require('bitcore-lib-cash');
const {BIP32Factory} = require('bip32');
const ecc = require('tiny-secp256k1');
const ethUtil = require('ethereumjs-util');
const secp256k1 = require("secp256k1");
const { keccak224, keccak384, keccak256, keccak512 } = require('ethereum-cryptography/keccak');
const Address = require('litecore-lib/lib/address');
var ci = require('coininfo');

const main = async () => {
    //Initial Setup
    var mnemonic = BIP39.generateMnemonic();
    var passphrase = "12345678";

    const bip32 = BIP32Factory(ecc);
    var network = Bitcoin.networks['bitcoin'];

    const bitcoinDerivationPath = "m/44'/0'/0'/0/0";

    const seed = BIP39.mnemonicToSeedSync(mnemonic, passphrase);
    const masterNode = bip32.fromSeed(seed);

    let bitcoinAccountNode = masterNode
        .deriveHardened(44)
        .deriveHardened(0)
        .deriveHardened(0)
        .derive(0)
        .derive(0);

    //Legacy address = P2PKH
    const legacy = Bitcoin.payments.p2pkh({
        pubkey: bitcoinAccountNode.publicKey,
        network: network,
    });

    //SegWit address - P2WPKH
    const segwit = Bitcoin.payments.p2wpkh({
        pubkey: bitcoinAccountNode.publicKey,
        network: network,
    })

    const privateKey = bitcoinAccountNode.toWIF();

    console.log("Bitecoin Private Key: ", privateKey);
    console.log("Bitecoin SegWit Address: ", segwit.address);
    console.log("Bitecoin Legacy Address: ", legacy.address);

}

main();