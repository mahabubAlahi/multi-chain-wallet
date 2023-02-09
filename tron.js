const TronWeb = require('tronweb');
const BIP39 = require('bip39');
const {BIP32Factory} = require('bip32');
const ecc = require('tiny-secp256k1');
var ci = require('coininfo')


const main = async() => {
    var mnemonic = BIP39.generateMnemonic();
    var passphrase = "12345678";
    const bip32 = BIP32Factory(ecc);
    const seed = BIP39.mnemonicToSeedSync(mnemonic, passphrase);
    const masterNode = bip32.fromSeed(seed);
    let tronAccountNode = masterNode
        .deriveHardened(44)
        .deriveHardened(195)
        .deriveHardened(0)
        .derive(0)
        .derive(0);
    let tronAccountNode1 = masterNode
        .deriveHardened(44)
        .deriveHardened(195)
        .deriveHardened(0)
        .derive(0)
        .derive(1);
    //var privateKey = crypto.randomBytes(32).toString('hex');
    const privateKey = tronAccountNode.privateKey.toString('hex');
    const privateKey1 = tronAccountNode1.privateKey.toString('hex');
    console.log("Private Key", privateKey);
    console.log("Private Key1", privateKey1);
    
    const HttpProvider = TronWeb.providers.HttpProvider;
    const fullNode = new HttpProvider("https://api.trongrid.io");
    const solidityNode = new HttpProvider("https://api.trongrid.io");
    const eventServer = new HttpProvider("https://api.trongrid.io");
    const tronWeb = new TronWeb(fullNode,solidityNode,eventServer,privateKey);
    const tronWeb1 = new TronWeb(fullNode,solidityNode,eventServer,privateKey1);
    
    const wallet = await tronWeb.createAccount();
    const wallet1 = await tronWeb1.createAccount();
    console.log(wallet);
    console.log(wallet1);
}

main()
