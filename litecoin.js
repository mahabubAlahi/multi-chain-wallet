const BIP39 = require('bip39');
const {BIP32Factory} = require('bip32');
const ecc = require('tiny-secp256k1');
const litecore = require('bitcore-lib-ltc');
const ci = require('coininfo');

const main = async() => {
    var mnemonic = BIP39.generateMnemonic();
    var passphrase = "12345678";

    const bip32 = BIP32Factory(ecc);

    const litecoinDerivationPath = "m/44'/2'/0'/0/0";
    const seed = BIP39.mnemonicToSeedSync(mnemonic, passphrase);
    const masterNode = bip32.fromSeed(seed);

    let litecoinAccountNode = masterNode
      .deriveHardened(44)
      .deriveHardened(2)
      .deriveHardened(0)
      .derive(0)
      .derive(0);

      const litecoinprivateKey = new litecore.HDPrivateKey(litecoinAccountNode.toBase58());

      var a = litecore.Address.fromPublicKey(litecoinprivateKey.hdPublicKey.publicKey);

      console.log(a.toString());
}

main();