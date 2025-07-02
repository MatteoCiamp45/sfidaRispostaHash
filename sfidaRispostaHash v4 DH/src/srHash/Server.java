package srHash;

import srHash.Utils.CertUtil;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

public class Server {
    private KeyPair keyPair;               // coppia chiavi asimmetriche per DH
    private byte[] sharedSecret;           // segreto ottenuto da DH
    private byte[] currentChallenge;       // nonce Rb
    private PrivateKey rsaPrivateKey;      // chiave privata RSA per firmare
    private X509Certificate serverCert;    // certificato X.509 del server
    private X509Certificate clientCert;    // certificato X.509 del client

    private TimeMarkerInterface tms = new TimeMarker();


    public Server() throws Exception {

        // 1. Carica chiave privata RSA e certificato X.509 dal filesystem
        this.rsaPrivateKey = CertUtil.loadPrivateKeyPEM("src/srHash/Utils/server.key");
        this.serverCert = CertUtil.loadCertificate("src/srHash/Utils/server.crt");

        // Genera la chiave DH e i parametri (p, g)
        this.keyPair = generateDHKeyPair();
    }

    // Generazione DH locale
    private KeyPair generateDHKeyPair() throws Exception {
        // Crea un generatore di parametri crittografici
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(2048);
        // genera p e g
        AlgorithmParameters params = paramGen.generateParameters();                 // p e g
        DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);    // inseriti in una struttura DHParameterSpec per inizializzare il generatore di chiavi

        // Crea un generatore di coppie di chiavi per l’algoritmo Diffie-Hellman
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");      // generatore di chiavi
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();                                            // coppia di chiavi (privata e pubblica) DH
    }

    // Per passare i parametri DH (p, g) al client
    public DHParameterSpec getDHParameterSpec() {
        return ((DHPublicKey) keyPair.getPublic()).getParams();
    }

    public PublicKey getDHPublicKey() {
        return keyPair.getPublic(); // chiave pubblica per il client
    }

    public X509Certificate getCertificate() {
        return serverCert;
    }

    public void setClientCertificate(X509Certificate cert) {
        this.clientCert = cert;
        try {
            clientCert.checkValidity(); // verifica data
        } catch (CertificateExpiredException e) {
            throw new RuntimeException(e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException(e);
        }
    }

    // Firma la chiave pubblica DH (encoded) con la chiave privata RSA
    public byte[] signDHPublicKey() throws Exception {
        byte[] dhPubEncoded = keyPair.getPublic().getEncoded();
        System.out.println("Server: firma chiave pubblica del DH");
        return CertUtil.sign(dhPubEncoded, rsaPrivateKey);
    }

    // Riceve la chiave pubblica del client e calcola il segreto condiviso `s`
    public void receiveClientPublicKey(byte[] dhPubEncoded, byte[] signature) throws Exception {
        if (verifyClientPublicKeySignature(dhPubEncoded, signature)) {
            System.out.println("Server: firma del client certificata");
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey clientPubKey = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(dhPubEncoded));

            this.sharedSecret = computeSharedSecret(keyPair.getPrivate(), clientPubKey);
            System.out.println("Server: segreto condiviso calcolato.");
        } else {
            throw new SecurityException("Firma del client sulla chiave pubblica DH non valida!");
        }
    }

    // Verifica la firma della chiave pubblica DH con il certificato del server
    private boolean verifyClientPublicKeySignature(byte[] data, byte[] signature) throws Exception {
        return CertUtil.verify(data, signature, clientCert);    // verifica la firma del client, usando la chiave pubblica contenuta nel certificato clientCert
    }

    // Calcolo del segreto condiviso 's'
    private byte[] computeSharedSecret(PrivateKey privKey, PublicKey pubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        byte[] raw = ka.generateSecret();       // g^(ab) mod p
        return deriveKey(raw);
    }

    private byte[] deriveKey(byte[] shared) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(shared);
    }

    public byte[] generateChallenge() throws IOException {
        ByteArrayOutputStream res = new ByteArrayOutputStream( );
        this.currentChallenge = new byte[16];
        new SecureRandom().nextBytes(currentChallenge);
        res.write(this.currentChallenge);
        System.out.println("Server: Rb: " + HexFormat.of().formatHex(this.currentChallenge));

        byte[] challenge = null;
        try {
            challenge = tms.generateMark(currentChallenge, "Server");
            System.out.println("Server: challenge con marca temporale: " + HexFormat.of().formatHex(challenge));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        res.write(challenge);

        System.out.println("Server: inviata sfida (Rb).");
        return res.toByteArray();           // res = Rb + mark
    }

    public void verifyResponse(byte[] response) throws Exception {
        byte[] expected = computeHash(currentChallenge, sharedSecret);
        System.out.println("Server: calcolo H(Rb || s): " + HexFormat.of().formatHex(expected));

        ByteBuffer buffer = ByteBuffer.wrap(response);
        byte[] res = new byte[32];
        buffer.get(res);                     // estrae Rb||s da challenge
        System.out.println("Server: ricevuto H(Rb || s): " + HexFormat.of().formatHex(res));
        byte[] mark = new byte[44];
        buffer.get(mark);                   // estrae marca

        if (tms.verifyMark(res, "clientA", mark)) {
            System.out.println("Server: messaggio verificato tramite marca temporale");
            if (Arrays.equals(expected, res)) {
                System.out.println("Server: risposta corretta. Identificazione riuscita");
            } else {
                System.out.println("Server: risposta errata. Identificazione fallita");
            }
        } else {
            System.out.println("Server: marca temporale non valida. Messaggio rigettato.");
        }

    }

    private byte[] computeHash(byte[] challenge, byte[] secret) throws Exception {
        byte[] input = new byte[challenge.length + secret.length];
        System.arraycopy(challenge, 0, input, 0, challenge.length);
        System.arraycopy(secret, 0, input, challenge.length, secret.length);
        return MessageDigest.getInstance("SHA-256").digest(input);
    }
}