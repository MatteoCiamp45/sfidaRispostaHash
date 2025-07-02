/*
N.B. B deve passare i parametri DH (p, g) a A affinché A possa generare una chiave compatibile.
    A: pubA = g^a mod p
    B: pubB = g^b mod p


PROTOCOLLO IDENTIFICAZIONE:
    1) Registrazione:
            - protocollo Ephemeral Diffie Hellman
            - ottenimento segreto condiviso 's'
    2) Identificazione:
            - protocollo sfida/risposta con hashing
            - aggiunta di marca temporale ai messaggi (marca: timestamp + counter + hash)
                                                      (hash: message, id, timestamp, counter)

 */

package srHash;

import srHash.Utils.CertUtil;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) throws Exception {

        Server server = new Server();

        /********** REGISTRAZIONE **********/
        System.out.println("REGISTRAZIONE");

        // 1. Il client carica il certificato del server
        X509Certificate serverCert = server.getCertificate();

        // 2. Il server genera i parametri DH e la propria coppia di chiavi
        DHParameterSpec dhParams = server.getDHParameterSpec();

        // 3. Il client riceve i parametri DH del server e genera una chiave compatibile
        Client client = new Client(dhParams, serverCert);

        // 4. Il server carica il certificato del client
        X509Certificate clientCert = client.getCertificate();
        server.setClientCertificate(clientCert);

        // 4. Il server firma la propria chiave pubblica DH e la invia assieme alla chiave pubblica
        byte[] serverDHPubEncoded = server.getDHPublicKey().getEncoded();   // chiave
        byte[] signatureS = server.signDHPublicKey();                       // firma su chiave

        // 5. Il client firma la propria chiave pubblica DH e la invia assieme alla chiave pubblica
        byte[] clientDHPubEncoded = client.getDHPublicKey().getEncoded();
        byte[] signatureC = client.signDHPublicKey();

        // 5. Scambio delle chiavi pubbliche per generare il segreto condiviso `s`
        client.receiveServerPublicKey(serverDHPubEncoded, signatureS);
        server.receiveClientPublicKey(clientDHPubEncoded, signatureC);

        /********** IDENTIFICAZIONE **********/
        System.out.println("IDENTIFICAZIONE");

        // 6. Il server genera la sfida (Rb) da inviare al client
        System.out.println("Server -> Client");
        byte[] challenge = server.generateChallenge();

        // 7. Il client calcola la risposta: H(Rb || s)
        System.out.println("Client -> Server");
        byte[] response = client.respondToChallenge(challenge);

        System.out.println("Verifica Server in corso ...");
        // 8. Il server verifica se la risposta è corretta
        server.verifyResponse(response);
    }
}

/*
FUNZIONAMENTO:


               [1] Diffie-Hellman autenticato con PKI (mutuo)
           ┌────────┐                        ┌────────┐
           │  Client│                        │ Server │
           └────────┘                        └────────┘
              │     richiede parametri DH       │
              │ ◄────────────────────────────── │
              │                                 │
              │ genera chiave DH con (p, g)     │
              │                                 │
              │ certC + pubC + firma(pubC)      │
              │ ──────────────────────────────► │
              │                                 │
              │                                 │ verifica certC e firma(pubC)
              │                                 │
              │                                 │
              │ certS + pubS + firma(pubS)      │
              │ ◄────────────────────────────── │
              │                                 │
              │ verifica certS e firma(pubS)    │
              │                                 │
    deriva s = g^(ab) mod p            deriva s = g^(ab) mod p

                   [2] Challenge / Response (identificazione)
              │          genera Rb              │
              │ ◄────────────────────────────── │
              │                                 │
              │     H(Rb || s) (firma implicita)│
              │ ──────────────────────────────► │
              │                                 │
              │                    verifica H(Rb || s)
              │                                 │
              │                                 │
              │                                 │
                    ==> autenticazione OK


*/