const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

const key = ec.genKeyPair();
const publicKey = key.getPublic('hex');
const privateKey = key.getPrivate('hex');

console.log();
console.log('Su clave pública (también su dirección de billetera, que se puede compartir libremente)\n', publicKey);

console.log();
console.log('Su clave privada (mantenga esta en secreto! Para firmar transacciones) \n ', privateKey);