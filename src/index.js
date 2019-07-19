const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const { Blockchain, Transaction } = require('./blockchain')


/*
console.log('Minando bloque.........')
L0L1coin.agregarBloque(new Block('16/10/19', { cantidad: 20 }))
console.log('Minando bloque.........')
L0L1coin.agregarBloque(new Block('17/10/19', { cantidad: 30 }))
console.log('Minando bloque.........')
L0L1coin.agregarBloque(new Block('18/10/19', { cantidad: 20 }))

console.log(L0L1coin.validarChain())
    //L0L1coin.chain[1].data = { cantidad: 300 }
    //L0L1coin.chain[1].hash = L0L1coin.chain[1].calcularHash()
    //console.log(L0L1coin.validarChain())
*/
const myKey = ec.keyFromPrivate('7c4c45907dec40c91bab3480c39032e90049f1a44f3e18c3e07c23e3273995cf');
const myWalletAddress = myKey.getPublic('hex');

let L0L1coin = new Blockchain();
const tx1 = new Transaction(myWalletAddress, 'address2', 100);
tx1.signTransaction(myKey);
L0L1coin.addTransaction(tx1);
//Minando

L0L1coin.minePendingTransactions(myWalletAddress);

//Segunda Transaccion
const tx2 = new Transaction(myWalletAddress, 'address1', 50);
tx2.signTransaction(myKey);
L0L1coin.addTransaction(tx2);
//Minando
L0L1coin.minePendingTransactions(myWalletAddress);

console.log();
console.log(`El balance de Lenin ${L0L1coin.getBalanceOfAddress(myWalletAddress)}`);

// Descomente esta línea si desea probar la manipulación de la cadena
//L0L1coin.chain[1].Transacciones[0].amount = 10;
// Comprobar si la cadena es válida
console.log();
console.log('Blockchain es valida?', L0L1coin.isChainValid() ? 'Yes' : 'No');