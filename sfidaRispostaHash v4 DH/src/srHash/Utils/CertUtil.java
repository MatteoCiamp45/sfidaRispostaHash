package srHash.Utils;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CertUtil {

    // Carica il certificato X.509 da file PEM o DER
    public static X509Certificate loadCertificate(String path) throws Exception {
        try (FileInputStream fis = new FileInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    // Carica la chiave privata RSA da file PEM PKCS#8
    public static PrivateKey loadPrivateKeyPEM(String path) throws Exception {
        String keyPEM = new String(Files.readAllBytes(Path.of(path)));
        keyPEM = keyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // Firma i dati con SHA256withRSA
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    // Verifica la firma su dati con la chiave pubblica del certificato
    public static boolean verify(byte[] data, byte[] signature, java.security.cert.Certificate cert) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(cert);
        sig.update(data);
        return sig.verify(signature);
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}