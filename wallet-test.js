/*var Bitcoin = require('bitcoinjs-lib');
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


//Initial Setup
/*var mnemonic = BIP39.generateMnemonic();
var passphrase = "12345678";

var masterHex = BIP39.mnemonicToSeed(mnemonic, passphrase);
var network = Bitcoin.networks['bitcoin'];
//var masterHDNode = Bitcoin.HDNode.fromSeedBuffer(masterHex, network);
const bip32 = BIP32Factory(ecc);

//Bitcoin Wallet
/*var accountZero = masterHDNode.deriveHardened(44).deriveHardened(0).deriveHardened(0);
var privateKey = accountZero.toBase58();
var address = accountZero.neutered().toBase58();

console.log("Private Key: ", privateKey);
console.log("Address: ", address);*/
/*
const bitcoin = require('bitcoinjs-lib')
const pubKey = bitcoin.HDNode.fromBase58('ypub6XMTwf6NSvfzYYgVgdNWRNfMTiQt4rSjZbEk8qoCnBGhUD2rsgZ2A8pexgzaGLKgySZxqxrctDpAVU8QtfxqfX8QUAhtFmGFUFx9B51TVg8')
  .derive(0)
  .derive(27)
  .getPublicKeyBuffer()

const { address } = bitcoin.payments.p2sh({
  redeem: bitcoin.payments.p2wpk({
    pubkey: pubKey
  })
})
*/

/*const bitcoinDerivationPath = "m/44'/0'/0'/0/0";
const etherumDerivationPath = "m/44'/60'/0'/0/0";
const litecoinDerivationPath = "m/44'/2'/0'/0/0";
const bitcoinCashDerivationPath = "m/44'/145'/0'/0/0";
const seed = BIP39.mnemonicToSeedSync(mnemonic, passphrase);
const masterNode = bip32.fromSeed(seed);
console.log("Masternode: ", masterNode);

//Bitcoin Wallet
const bitcoinAccountNode = masterNode.derivePath(bitcoinDerivationPath);
console.log(bitcoinAccountNode)

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

//Ethereum Wallet
const ethereumAccountNode = masterNode.derivePath(etherumDerivationPath);
console.log(ethereumAccountNode);
const ethereumHDAccountNode = hdkey.fromExtendedKey(ethereumAccountNode.toBase58());
console.log(ethereumAccountNode);
const ethereumWallet = ethereumHDAccountNode.getWallet();

console.log(ethereumWallet);

const ethereumPrivateKey = ethereumWallet.getPrivateKey();
//const ethereumAddress = ethUtil.toChecksumAddress(ethUtil.privateToAddress(ethereumPrivateKey).toString('hex'));

const hexAddress = ethUtil.privateToAddress(ethereumPrivateKey).toString('hex');
const ethereumAddress = ethUtil.toChecksumAddress('0x' + hexAddress);

console.log("Ethereum Private Key: ", ethereumPrivateKey);
console.log("Ethereum Address: ", ethereumAddress);

//Litecoin Wallet
/*const litecoinAccountNode = masterNode.derivePath(litecoinDerivationPath);

const litecoinPrivateKey = litecoinAccountNode.toBase58();
const litecoinAddress = litecoinAccountNode.neutered().toBase58();

let v1 = Buffer.from(secp256k1.publicKeyCreate(litecoinAccountNode.privateKey, true));

let final = keccak256(v1).slice(-20);

console.log("Litecoin Private Key: ", litecoinPrivateKey);
console.log("Litecoin Address: ", final.toString('hex'));*/

//Bitcoin Cash Wallet
//const bitcoinCashAccountNode = masterNode.derivePath(bitcoinCashDerivationPath);
/*let bitcoinCashAccountNode = masterNode
      .deriveHardened(44)
      .deriveHardened(145)
      .deriveHardened(0)
      .derive(0)
      .derive(0);
console.log(bitcoinCashAccountNode.toBase58());
console.log(bitcoinCashAccountNode.neutered().toBase58())

//const derivedPrivKey = xpriv.derive(path);

const bitecoinCashprivateKey = new bitcore.HDPrivateKey(bitcoinCashAccountNode.toBase58(), 'livenet');
/*const derivedPrivKey = bitecoinCashprivateKey.derive(bitcoinCashDerivationPath);
const privKey = derivedPrivKey.privateKey.toString('hex');
const pubKeyObj = derivedPrivKey.hdPublicKey;
    
    const bitecoinCashPublicKey = new bitcore.HDPublicKey(bitcoinCashAccountNode.neutered().toBase58());
    const pubKey = bitecoinCashPublicKey.toString('hex');
    const pubKeyBuffer = bitecoinCashPublicKey.toBuffer();
    console.log(pubKeyBuffer);*/
    /*var hdPublicKey = bitecoinCashprivateKey.hdPublicKey;
    const test = hdPublicKey.publicKey.toBuffer();
    console.log(test);
    const hash = bitcore.crypto.Hash.sha256(test);
    const bn   = bitcore.crypto.BN.fromBuffer(hash);
    //const address = bitcore.Address.fromPublicKey(bitecoinCashPublicKey);
    var address = new bitcore.Address(bn, 'livenet');
/*const bitecoinCashPublicKey = new bitcore.HDPublicKey(bitecoinCashprivateKey);
console.log(bitecoinCashPublicKey)
const hash = bitcore.crypto.Hash.sha256(bitecoinCashPublicKey);
const bn   = bitcore.crypto.BN.fromBuffer(bitecoinCashPublicKey);
const address = new bitcore.Address(bn, "testnet");*/

/*const seed = bip39.mnemonicToSeed(mnemonic);
const hash = bch.crypto.Hash.sha256(seed);
const bn   = bch.crypto.BN.fromBuffer(hash);
const key  = new bch.PrivateKey(bn);
const wif  = key.toWIF();*/

//const bitcoinCashAccountNode = masterNode.derivePath(bitcoinCashDerivationPath);
//console.log("BitcoinCashAccountNode", bitcoinCashAccountNode)
//console.log("seed", seed);

//const litecoinAccountNode = masterNode.derivePath(litecoinDerivationPath);
/*let litecoinAccountNode = masterNode
      .deriveHardened(44)
      .deriveHardened(2)
      .deriveHardened(0)
      .derive(0)
      .derive(0);*/
//const litecoinHDAccountNode = HDKey.fromExtendedKey(litecoinAccountNode.toBase58(), ci('LTC').versions.bip32);
//console.log(litecoinHDAccountNode);
/*const litecoinWallet = litecoinHDAccountNode.getWallet();

console.log(litecoinWallet);

//const litecoinPrivateKey = litecoinWallet.getPrivateKey();
//const ethereumAddress = ethUtil.toChecksumAddress(ethUtil.privateToAddress(ethereumPrivateKey).toString('hex'));

const hex2Address = ethUtil.privateToAddress(litecoinPrivateKey).toString('hex');
const litecoinAddress = ethUtil.toChecksumAddress('0x' + hex2Address);

console.log("Litecoin Private Key: ", litecoinPrivateKey);
console.log("Litecoin Address: ", litecoinAddress);*/

/*

 public static fromExtendedPrivateKey(extendedPrivateKey: string): Wallet {
    if (extendedPrivateKey.slice(0, 4) !== 'xprv') {
      throw new Error('Not an extended private key')
    }
    const tmp: Buffer = bs58check.decode(extendedPrivateKey)
    if (tmp[45] !== 0) {
      throw new Error('Invalid extended private key')
    }
    return Wallet.fromPrivateKey(tmp.slice(46))
  }

export const privateToPublic = function (privateKey: Buffer): Buffer {
  assertIsBuffer(privateKey)
  // skip the type flag and use the X, Y points
  return Buffer.from(publicKeyCreate(privateKey, false)).slice(1)
}

HDKey.fromExtendedKey = function (base58key, versions) {
  // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
  versions = versions || BITCOIN_VERSIONS;
  var hdkey = new HDKey(versions);

  var keyBuffer = bs58check.decode(base58key);

  var version = keyBuffer.readUInt32BE(0);
  assert(version === versions.private || version === versions.public, 'Version mismatch: does not match private or public');

  hdkey.depth = keyBuffer.readUInt8(4);
  hdkey.parentFingerprint = keyBuffer.readUInt32BE(5);
  hdkey.index = keyBuffer.readUInt32BE(9);
  hdkey.chainCode = keyBuffer.slice(13, 45);

  var key = keyBuffer.slice(45);
  if (key.readUInt8(0) === 0) { // private
    assert(version === versions.private, 'Version mismatch: version does not match private');
    hdkey.privateKey = key.slice(1); // cut off first 0x0 byte
  } else {
    assert(version === versions.public, 'Version mismatch: version does not match public');
    hdkey.publicKey = key;
  }

  return hdkey
};
*/





  