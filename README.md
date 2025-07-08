# PROGETTO SICUREZZA

## Protocollo Sfida/Risposta con Hash

Il protocollo di autenticazione **sfida/risposta (challenge/response)** con **hash** consente a un server (B) di verificare l’identità di un client (A) tramite una sfida casuale e una risposta basata su un valore segreto condiviso.

### Funzionamento Base

1. **Sfida (Challenge):** Il server invia al client un valore casuale `Rb`.
2. **Risposta (Response):** Il client combina `Rb` con il segreto condiviso e calcola l’hash: response = H(Rb || segreto)
3. **Verifica:** Il server calcola lo stesso hash e lo confronta con la risposta ricevuta. Se coincidono, il client è autenticato.

### Implementazione Semplice

1. Il server crea un **nonce** `Rb`.
2. Invia `Rb` al client A.
3. Il client calcola `r = H(Rb || s)`.
4. Il client invia `r` al server B.
5. Il server verifica `r`.

### Condivisione del Segreto

Poiché client e server non si conoscono a priori, si usa il **protocollo Diffie-Hellman (DH)** per derivare il segreto `s`.

#### Scambio DH:

1. Il server B stabilisce parametri `p` e `g`, e li invia ad A.
2. Entrambi generano chiavi private e pubbliche DH.
3. Si scambiano le chiavi pubbliche.
4. Calcolano il segreto condiviso `s = g^(ab) mod p`.

---

## Vulnerabilità della Versione Base

1. **Assenza di Autenticazione durante DH:**  
Un attaccante può intercettare le chiavi pubbliche e stabilire due segreti (s1 con A, s2 con B), impersonando entrambe le parti (attacco man-in-the-middle).

2. **Attacco Replay:**  
Un attaccante può registrare una sfida `Rb` e la relativa risposta `H(Rb || s)`, riutilizzandole in futuro.

---

## Protocollo Aggiornato: Sfida/Risposta con Hash Sicuro

### 1. Registrazione Sicura tramite Diffie-Hellman Autenticato

- Il server:
- Genera parametri DH (`p`, `g`) e una coppia di chiavi.
- Firma la propria chiave pubblica DH con un certificato.
- Il client:
- Riceve i parametri, genera la propria coppia di chiavi.
- Firma la chiave pubblica e la invia con un certificato.
- Entrambe le parti:
- Verificano i certificati e le firme reciproche.
- Derivano il **segreto condiviso `s`** da DH.

### 2. Autenticazione Tramite Sfida/Risposta con Marca Temporale

1. Il server genera una sfida casuale `Rb` e la marca temporale `T`, inviandole al client.
2. Il client calcola: response = H(Rb || s || T)
3. Il client invia la risposta e la marca temporale al server.
4. Il server verifica che la risposta sia corretta e che `T` sia valida e unica.

---

## Sicurezza Garantita

- Solo chi conosce il segreto `s` derivato da DH e ha certificati validi può autenticarsi.
- L’autenticazione è **reciproca**.
- L’uso della **marca temporale** impedisce gli **attacchi di replay**.
- La marca temporale è ispirata a TSS (Trusted Secure Systems) e identifica **univocamente**:
  1. Un messaggio,
  2. Un utente,
  3. Un istante temporale.

---

## Conclusione

Questo protocollo offre:
- Autenticazione forte tramite chiavi DH firmate.
- Protezione contro man-in-the-middle e replay.
- Scalabilità in ambienti senza segreti precondivisi.

