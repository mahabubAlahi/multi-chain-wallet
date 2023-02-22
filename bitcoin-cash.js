const BIP39 = require('bip39');
var bitcore = require('bitcore-lib-cash');
const {BIP32Factory} = require('bip32');
const ecc = require('tiny-secp256k1');
var ci = require('coininfo')

const main = async() => {
    var mnemonic = BIP39.generateMnemonic();
    var passphrase = "12345678";

    const bip32 = BIP32Factory(ecc);

    const bitcoinCashDerivationPath = "m/44'/145'/0'/0/0";
    const seed = BIP39.mnemonicToSeedSync(mnemonic, passphrase);
    const masterNode = bip32.fromSeed(seed);

    let bitcoinCashAccountNode = masterNode
      .deriveHardened(44)
      .deriveHardened(145)
      .deriveHardened(0)
      .derive(0)
      .derive(0);

    let bitcoinCashAccountNode1 = masterNode
      .deriveHardened(44)
      .deriveHardened(145)
      .deriveHardened(0)
      .derive(0)
      .derive(1);


    const bitecoinCashprivateKey = new bitcore.HDPrivateKey(bitcoinCashAccountNode.toBase58(), 'livenet');
    const bitecoinCashprivateKey1 = new bitcore.HDPrivateKey(bitcoinCashAccountNode1.toBase58(), 'livenet');

    //console.log(bitecoinCashprivateKey)

    //var pubkey = new bitcore.HDPublicKey(bitcoinCashAccountNode.neutered().toBase58(), 'livenet');

    //console.log(bitecoinCashprivateKey.hdPublicKey.publicKey)

    var a = bitcore.Address.fromPublicKey(bitecoinCashprivateKey.hdPublicKey.publicKey, 'livenet');
    var a1 = bitcore.Address.fromPublicKey(bitecoinCashprivateKey1.hdPublicKey.publicKey, 'livenet');

    console.log(a.toCashAddress());
    console.log(a1.toCashAddress());
}

main();