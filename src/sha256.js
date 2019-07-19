const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
class Sha256 {
    static hash(msg, options) {
        const defaults = { msgFormat: 'string', outFormat: 'hex' };
        const opt = Object.assign(defaults, options);

        // Tenga en cuenta el uso a lo largo de esta rutina de 'n >>> 0' para coaccionar numero 'n' a entero de 32 bits sin signo
        //console.log("SHA256");
        //console.log("El mensaje que Cera Hasheado -> " + msg);

        switch (opt.msgFormat) {
            default: // el valor predeterminado es convertir la cadena a UTF-8, ya que SHA solo trata con flujos de bytes
                case 'string':
            {
                msg = utf8Encode(msg);
            }

            break;
            case 'hex-bytes':
                {
                    msg = hexBytesToString(msg);
                }
                break;
        }

        // constantes para el hash
        const K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];


        /* valor hash inicial [§5.3.3]
        El valor hash inicial H es la siguiente secuencia de palabras de 32 bits
        (que se obtienen al tomar las partes fraccionarias de las raíces cuadradas de los primeros ocho primos): */

        const H = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];

        // PREPROCESAMIENTO 

        msg += String.fromCharCode(0x80); // agregar el bit '1' al final (+ relleno de 0) a la cadena [§5.1.1]
        // convertir la cadena msg en bloques de 512 bits (matriz de 16 enteros de 32 bits) [§5.2.1]
        const l = msg.length / 4 + 2; // longitud (en enteros de 32 bits) de msg + ‘1’ + longitud agregada
        const N = Math.ceil(l / 16); // numero de bloques de 16 enteros (512 bits) necesarios para contener "l" ints
        const M = new Array(N); //el mensaje M es una matriz N × 16 de enteros de 32 bits
        //console.log(l);
        //console.log(N);
        //console.log(JSON.stringify(M));


        for (let i = 0; i < N; i++) {
            M[i] = new Array(16);
            for (let j = 0; j < 16; j++) { //codificar 4 caracteres por entero (64 por bloque), codificación big-endian
                M[i][j] = (msg.charCodeAt(i * 64 + j * 4 + 0) << 24) | (msg.charCodeAt(i * 64 + j * 4 + 1) << 16) |
                    (msg.charCodeAt(i * 64 + j * 4 + 2) << 8) | (msg.charCodeAt(i * 64 + j * 4 + 3) << 0);
            } // la nota que sale del final de msg está bien, ya que las operaciones a nivel de bit en NaN devuelven 0
        }
        //console.log(JSON.stringify(M));

        // agregue la longitud (en bits) al par final de enteros de 32 bits 
        // nota: la palabra más significativa sería (len-1) * 8 >>> 32, pero ya que JS convierte
        // operar bit a bit a 32 bits, necesitamos simular esto mediante operadores aritméticos
        const lenHi = ((msg.length - 1) * 8) / Math.pow(2, 32);
        const lenLo = ((msg.length - 1) * 8);
        M[N - 1][14] = Math.floor(lenHi);
        M[N - 1][15] = lenLo;
        //console.log(JSON.stringify(M));


        // HASH COMPUTATION [§6.2.2]

        for (let i = 0; i < N; i++) {
            const W = new Array(64);

            // 1 - prepare message schedule 'W'
            for (let t = 0; t < 16; t++) W[t] = M[i][t];
            for (let t = 16; t < 64; t++) {
                W[t] = (Sha256.σ1(W[t - 2]) + W[t - 7] + Sha256.σ0(W[t - 15]) + W[t - 16]) >>> 0;
                //console.log(JSON.stringify(W));
            }

            // 2 - Se inicializa las variable a,b,c,d,e,f,g,h con el hash inicializado
            let a = H[0],
                b = H[1],
                c = H[2],
                d = H[3],
                e = H[4],
                f = H[5],
                g = H[6],
                h = H[7];

            // 3 - main loop (note '>>> 0' for 'addition modulo 2^32')
            for (let t = 0; t < 64; t++) {
                const T1 = h + Sha256.Σ1(e) + Sha256.Ch(e, f, g) + K[t] + W[t];
                const T2 = Sha256.Σ0(a) + Sha256.Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = (d + T1);
                d = c;
                c = b;
                b = a;
                a = (T1 + T2);
                //console.log(JSON.stringify(a, b, c, d, e, f, g, h));

            }

            // 4 - calcular el nuevo valor hash intermedio 
            H[0] = (H[0] + a);
            H[1] = (H[1] + b);
            H[2] = (H[2] + c);
            H[3] = (H[3] + d);
            H[4] = (H[4] + e);
            H[5] = (H[5] + f);
            H[6] = (H[6] + g);
            H[7] = (H[7] + h);
            //console.log(JSON.stringify(H));
        }

        // convertiremos  H0..H7 en hexadecimal (con ceros iniciales)
        for (let h = 0; h < H.length; h++) {
            H[h] = ('00000000' + H[h].toString(16)).slice(-8);
            //console.log(JSON.stringify(H));
        }

        // concatenamos los H0..H7, con un separador para el condicional posterior
        const separator = opt.outFormat == 'hex-w' ? ' ' : '';
        return H.join(separator);

        /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

        function utf8Encode(str) {
            try {
                return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
            } catch (e) { // no TextEncoder available?
                return unescape(encodeURIComponent(str));
            }
        }

        function hexBytesToString(hexStr) { // convertir la cadena de números hexadecimales en una cadena de caracteres (por ejemplo, '616263' -> 'abc').
            const str = hexStr.replace(' ', ''); // se permite la separacion por grupos
            return str == '' ? '' : str.match(/.{2}/g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('');
        }
    }



    /**
     * Rotates right (cambio circular a la derecha) valor x por n posiciones 
     * @private
     */
    static ROTR(n, x) {
        return (x >>> n) | (x << (32 - n));
    }


    /**
     * Logical functions [§4.1.2].
     * @private
     */
    static Σ0(x) { return Sha256.ROTR(2, x) ^ Sha256.ROTR(13, x) ^ Sha256.ROTR(22, x); }
    static Σ1(x) { return Sha256.ROTR(6, x) ^ Sha256.ROTR(11, x) ^ Sha256.ROTR(25, x); }
    static σ0(x) { return Sha256.ROTR(7, x) ^ Sha256.ROTR(18, x) ^ (x >>> 3); }
    static σ1(x) { return Sha256.ROTR(17, x) ^ Sha256.ROTR(19, x) ^ (x >>> 10); }
    static Ch(x, y, z) { return (x & y) ^ (~x & z); } // 'choice'
    static Maj(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); } // 'majority'

}

module.exports = Sha256