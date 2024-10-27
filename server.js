const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const forge = require('node-forge');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// Endpoint for Classic RSA
app.post('/classic-rsa', (req, res) => {
    try {
        const { p, q, plaintext } = req.body;
        const primeP = parseInt(p);
        const primeQ = parseInt(q);
        const plainText = parseInt(plaintext);
        console.log(`Received values -> p: ${primeP}, q: ${primeQ}, plaintext: ${plainText}`);

        if (isNaN(primeP) || isNaN(primeQ) || isNaN(plainText)) {
            return res.status(400).json({ error: "Invalid input! Please provide valid numbers." });
        }

        const n = primeP * primeQ;
        const phi_n = (primeP - 1) * (primeQ - 1);
        let e = 0;

        for (let i = 2; i < phi_n; i++) {
            if (gcd(i, phi_n) === 1) {
                e = i;
                break;
            }
        }

        const d = modInverse(e, phi_n);
        const ciphertext = encrypt(plainText, e, n);
        const decryptedMessage = decrypt(ciphertext, d, n);

        res.json({
            n: n.toString(), // Convert BigInt to string
            phi_n: phi_n.toString(), // Convert BigInt to string
            e: e.toString(), // Convert BigInt to string
            d: d.toString(), // Convert BigInt to string
            ciphertext: ciphertext.toString(), // Convert BigInt to string
            decryptedMessage: decryptedMessage.toString() // Convert BigInt to string
        });
    } catch (error) {
        console.error("Error during Classic RSA processing:", error.message);
        res.status(500).json({ error: "An error occurred during Classic RSA processing.", details: error.message });
    }
});

// Endpoint for 2048-bit RSA
app.post('/rsa-2048', (req, res) => {
    try {
        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ error: 'Message is required.' });
        }

        const { privateKey, publicKey } = generateRSAKeyPair();
        const encryptedMessage = encrypt2048(message, publicKey);
        const decryptedMessage = decrypt2048(encryptedMessage, privateKey);

        res.json({
            encryptedMessage,
            decryptedMessage,
        });
    } catch (error) {
        console.error('2048-bit RSA error:', error);
        res.status(500).json({ error: 'An error occurred during 2048-bit RSA processing.', details: error.message });
    }
});

// Classic RSA functions
function gcd(a, b) {
    while (b) {
        [a, b] = [b, a % b];
    }
    return a;
}

function modInverse(e, phi) {
    let m0 = phi, x0 = 0, x1 = 1;
    if (phi === 1) return 0;

    while (e > 1) {
        let q = Math.floor(e / phi);
        [phi, e] = [e % phi, phi];
        [x0, x1] = [x1 - q * x0, x0];
    }

    return x1 < 0 ? x1 + m0 : x1;
}

function encrypt(m, e, n) {
    return BigInt(m) ** BigInt(e) % BigInt(n);
}

function decrypt(c, d, n) {
    return BigInt(c) ** BigInt(d) % BigInt(n);
}

// 2048-bit RSA functions
function generateRSAKeyPair() {
    const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);
    return {
        privateKey: forge.pki.privateKeyToPem(privateKey),
        publicKey: forge.pki.publicKeyToPem(publicKey),
    };
}

function encrypt2048(message, publicKeyPem) {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const encrypted = publicKey.encrypt(forge.util.encodeUtf8(message), 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
            md: forge.md.sha256.create(),
        },
    });
    return forge.util.encode64(encrypted);
}

function decrypt2048(encryptedMessage, privateKeyPem) {
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const decoded = forge.util.decode64(encryptedMessage);
    const decrypted = privateKey.decrypt(decoded, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
            md: forge.md.sha256.create(),
        },
    });
    return forge.util.decodeUtf8(decrypted);
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
