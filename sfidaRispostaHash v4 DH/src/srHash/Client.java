package srHash;

import srHash.Utils.CertUtil;

import javax.crypto.KeyAgreement;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import javax.crypto.spec.DHParameterSpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

public class Client {
    private KeyPair keyPair;
    private byte[] sharedSecret;
    private PrivateKey rsaPrivateKey;      // chiave privata RSA per firmare
    private X509Certificate clientCert;    // certificato X.509 del client
    private X509Certificate serverCert;

    private TimeMarkerInterface tms = new TimeMarker();



    public Client(DHParameterSpec dhParams, X509Certificate serverCert) throws Exception {
        this.serverCert = serverCert;
        try {
            serverCert.checkValidity(); // verifica data
        } catch (CertificateExpiredException e) {
            throw new RuntimeException(e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException(e);
        }
        this.keyPair = generateDHKeyPair(dhParams); // genera una chiave usando i parametri (p, g) del server

        this.rsaPrivateKey = CertUtil.loadPrivateKeyPEM("src/srHash/Utils/client.key");
        this.clientCert = CertUtil.loadCertificate("src/srHash/Utils/client.crt");

    }

    // Genera la chiave DH usando i parametri forniti
    private KeyPair generateDHKeyPair(DHParameterSpec dhSpec) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }

    public PublicKey getDHPublicKey() {
        return keyPair.getPublic();
    }

    public X509Certificate getCertificate() {
        return clientCert;
    }

    // Firma la chiave pubblica DH (encoded) con la chiave privata RSA
    public byte[] signDHPublicKey() throws Exception {
        byte[] dhPubEncoded = keyPair.getPublic().getEncoded();
        System.out.println("Client: firma chiave pubblica del DH");
        return CertUtil.sign(dhPubEncoded, rsaPrivateKey);
    }

    // Riceve la chiave pubblica del server e calcola il segreto condiviso `s`
    public void receiveServerPublicKey(byte[] dhPubEncoded, byte[] signature) throws Exception {
        if (verifyServerPublicKeySignature(dhPubEncoded, signature)) {
            System.out.println("Client: firma del server certificata");
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey serverPubKey = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(dhPubEncoded));

            this.sharedSecret = computeSharedSecret(keyPair.getPrivate(), serverPubKey);
            System.out.println("Client: segreto condiviso calcolato.");
        } else {
            throw new SecurityException("Firma del server sulla chiave pubblica DH non valida!");
        }
    }

    // Verifica la firma della chiave pubblica DH con il certificato del server
    private boolean verifyServerPublicKeySignature(byte[] data, byte[] signature) throws Exception {
        return CertUtil.verify(data, signature, serverCert);
    }

    // Calcolo del segreto condiviso s = g^(ab) mod p
    private byte[] computeSharedSecret(PrivateKey privKey, PublicKey pubKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privKey);                        // inizializza DH con la chiave privata locale
        ka.doPhase(pubKey, true);       // accordo con la chiave pubblica dell'altro partecipante
        byte[] raw = ka.generateSecret();        // risultato matematico dell’algoritmo DH tra le due chiavi (g^b)^a mod p = g^(ab) mod p
        return deriveKey(raw);
    }

    // Deriva chiave simmetrica SHA-256(s)
    private byte[] deriveKey(byte[] shared) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(shared);
    }

    public byte[] respondToChallenge(byte[] challenge) throws Exception {
        System.out.println("Client: ricevuto Rb. Calcolo H(Rb || s)...");

        if (challenge.length != 60)
            throw new IllegalArgumentException("Challenge length must be 60 bytes");

        ByteBuffer buffer = ByteBuffer.wrap(challenge);
        byte[] Rb = new byte[16];
        buffer.get(Rb);                     // estrae Rb da challenge
        System.out.println("Client: ricevuto Rb:" + HexFormat.of().formatHex(Rb));
        byte[] mark = new byte[44];
        buffer.get(mark);                   // estrae marca

        if(tms.verifyMark(Rb,"Server",mark)){
            System.out.println("Client: messaggio verificato tramite marca temporale");
            byte[] msg = computeHash(Rb, sharedSecret);
            System.out.println("Client: calcolo H(Rb || s): " + HexFormat.of().formatHex(msg));

            ByteArrayOutputStream res = new ByteArrayOutputStream( );
            res.write(msg);
            byte[] ch = null;
            try {
                ch = tms.generateMark(msg, "clientA");
                System.out.println("Client: risposta con marca temporale: " + HexFormat.of().formatHex(ch));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            res.write(ch);

            return res.toByteArray();           // res = H(Rb||s) + mark
        } else{
            System.out.println("Client: messaggio errato");
            return null;
        }

    }

    private byte[] computeHash(byte[] challenge, byte[] secret) throws Exception {
        byte[] input = new byte[challenge.length + secret.length];
        System.arraycopy(challenge, 0, input, 0, challenge.length);
        System.arraycopy(secret, 0, input, challenge.length, secret.length);
        return MessageDigest.getInstance("SHA-256").digest(input);
    }
}
