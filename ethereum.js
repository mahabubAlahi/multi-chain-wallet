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
var ci = require('coininfo')

const main = async() => {
    //Initial Setup
    var mnemonic = BIP39.generateMnemonic();
    var passphrase = "12345678";

    const bip32 = BIP32Factory(ecc);

    const etherumDerivationPath = "m/44'/60'/0'/0/0";

    const seed = BIP39.mnemonicToSeedSync(mnemonic, passphrase);
    const masterNode = bip32.fromSeed(seed);

    let ethereumAccountNode = masterNode
        .deriveHardened(44)
        .deriveHardened(60)
        .deriveHardened(0)
        .derive(0)
        .derive(0);

    const ethereumHDAccountNode = hdkey.fromExtendedKey(ethereumAccountNode.toBase58());
    console.log("first", ethereumAccountNode.privateKey);
    const ethereumWallet = ethereumHDAccountNode.getWallet();
    
    console.log(ethereumWallet);
    
    const ethereumPrivateKey = ethereumWallet.getPrivateKey();
    console.log("second: ", ethereumPrivateKey);
    //const ethereumAddress = ethUtil.toChecksumAddress(ethUtil.privateToAddress(ethereumPrivateKey).toString('hex'));
    
    const hexAddress = ethUtil.privateToAddress(ethereumPrivateKey).toString('hex');
    const ethereumAddress = ethUtil.toChecksumAddress('0x' + hexAddress);
    
    console.log("Ethereum Private Key: ", ethereumPrivateKey);
    console.log("Ethereum Address: ", ethereumAddress);
}

main()