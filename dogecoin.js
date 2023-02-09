const BIP39 = require('bip39');
const {BIP32Factory} = require('bip32');
const ecc = require('tiny-secp256k1');
const dogecore = require('bitcore-lib-doge');
const ci = require('coininfo')

const main = async() => {
    var mnemonic = BIP39.generateMnemonic();
    var passphrase = "12345678";

    const bip32 = BIP32Factory(ecc);

    const litecoinDerivationPath = "m/44'/3'/0'/0/0";
    const seed = BIP39.mnemonicToSeedSync(mnemonic, passphrase);
    const masterNode = bip32.fromSeed(seed);

    let dogeAccountNode = masterNode
      .deriveHardened(44)
      .deriveHardened(3)
      .deriveHardened(0)
      .derive(0)
      .derive(0);

      const dogeprivateKey = new dogecore.HDPrivateKey(dogeAccountNode.toBase58());

      var a = dogecore.Address.fromPublicKey(dogeprivateKey.hdPublicKey.publicKey);

      console.log(a.toString());
}

main();