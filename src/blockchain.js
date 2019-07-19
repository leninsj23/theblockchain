const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const Sha256 = require('./sha256')
class Transaction {
    constructor(fromAddress, toAddress, amount) {
        this.fromAddress = fromAddress
        this.toAddress = toAddress
        this.amount = amount
        this.timestamp = Date.now();

    }

    calculateHash() {
        return Sha256.hash(this.fromAddress + this.toAddress + this.amount + this.timestamp).toString
    }
    signTransaction(signingKey) {
        // Solo puede enviar una transacción desde la billetera que está vinculada a su
        // llave. Así que aquí comprobamos si la dirección coincide con su clave pública

        if (signingKey.getPublic('hex') !== this.fromAddress) {
            throw new Error('No puedes firmar transacciones para otras carteras!');
        }

        // Calcule el hash de esta transacción, firme con la clave 
        // y guárdelo dentro del objeto de transacción
        const hashTx = this.calculateHash();
        const sig = signingKey.sign(hashTx, 'base64');

        this.signature = sig.toDER('hex');
    }
    isValid() {
        if (this.fromAddress === null) return true;

        if (!this.signature || this.signature.length === 0) {
            throw new Error('Sin firma en esta transacción');
        }
        const publicKey = ec.keyFromPublic(this.fromAddress, 'hex');
        return publicKey.verify(this.calculateHash(), this.signature);
    }
}
class Block {
    constructor(timestamp, Transacciones, hashPrevio = '') {
        this.timestamp = timestamp
        this.Transacciones = Transacciones
        this.hashPrevio = hashPrevio
        this.hash = this.calcularHash()
        this.nonce = 0
    }

    calcularHash() {
        return Sha256.hash(this.timestamp + this.hashPrevio + JSON.stringify(this.data) + this.nonce).toString()
    }

    minarBloque(dificultad) {
        while (this.hash.substring(0, dificultad) !== Array(dificultad + 1).join('0')) {
            this.nonce++
                this.hash = this.calcularHash()
        }
        console.log('Bloque minado:' + this.hash)
    }

    hasValidTransactions() {
        for (const tx of this.Transacciones) {
            if (!tx.isValid()) {
                return false;
            }
        }

        return true;
    }
}
class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()]
        this.difficulty = 3
        this.pendingTransactions = []
        this.miningReward = 100
    }

    createGenesisBlock() {
        return new Block('19/07/2019', 'Bloque Genesis', '0')
    }
    getLatestBlock() {
        return this.chain[this.chain.length - 1]
    }

    /*
    agregarBloque(nuevoBloque) {
        nuevoBloque.hashPrevio = this.getLatestBlock().hash
        nuevoBloque.minarBloque(this.dificultad)
        this.chain.push(nuevoBloque)
    }*/

    addTransaction(transaction) {
        if (!transaction.fromAddress || !transaction.toAddress) {
            throw new Error('Tiene que contener un destinatario y un remitente');
        }

        // Verificacion de la transaccion
        if (!transaction.isValid()) {
            throw new Error('No se puede agregar una transacción no válida a la cadena');
        }

        if (transaction.amount <= 0) {
            throw new Error('El monto de la transacción debe ser mayor que 0');
        }

        this.pendingTransactions.push(transaction)
    }
    minePendingTransactions(addressMinero) {
        const rewardTx = new Transaction(null, addressMinero, this.miningReward);
        this.pendingTransactions.push(rewardTx);

        let block = new Block(Date.now(), this.pendingTransactions)
        block.hashPrevio = this.getLatestBlock().hash
        block.minarBloque(this.difficulty)
        console.log('Se ha minado Correctamente el Bloque')
        this.chain.push(block)

        this.pendingTransactions = [];

    }

    getBalanceOfAddress(address) {
        let balance = 0
        for (const block of this.chain) {
            for (const trans of block.Transacciones) {
                if (trans.fromAddress == address) {
                    balance -= trans.amount
                }

                if (trans.toAddress === address) {
                    balance += trans.amount
                }
            }
        }
        return balance
    }

    getAllTransactionsForWallet(address) {
        const txs = [];

        for (const block of this.chain) {
            for (const tx of block.Transacciones) {
                if (tx.fromAddress === address || tx.toAddress === address) {
                    txs.push(tx);
                }
            }
        }

        return txs;
    }

    isChainValid() {
        const realGenesis = JSON.stringify(this.createGenesisBlock());

        if (realGenesis !== JSON.stringify(this.chain[0])) {
            return false;
        }
        for (let i = 1; i < this.chain.length; i++) {
            const bloqueActual = this.chain[i]
            const bloqueAnterior = this.chain[i - 1]

            if (bloqueActual.hash != bloqueActual.calcularHash()) {
                return false
            }

            if (bloqueActual.hashPrevio != bloqueAnterior.hash) {
                return false
            }
        }
        return true
    }



}

module.exports.Blockchain = Blockchain
module.exports.Block = Block
module.exports.Transaction = Transaction