#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libsecurity.h"
#include "io.h"
#include "consts.h"

int state_sec = 0;
char *hostname = NULL;
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;

uint8_t client_nonce[NONCE_SIZE];
uint8_t server_nonce[NONCE_SIZE];

static uint64_t read_be_uint(const uint8_t* bytes, size_t nbytes) {
    // Hint: this is used for certificate lifetime fields.
    uint64_t result = 0;
    for (size_t i = 0; i < nbytes; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

static bool parse_lifetime_window(const tlv* life, uint64_t* start_ts, uint64_t* end_ts) {
    // Return false on malformed input (NULL pointers, wrong length, invalid range).
    if (life == NULL || life->type != LIFETIME || life->length != 16) return false; // lifetime must be 16 bytes (2 8-byte timestamps)
    *start_ts = read_be_uint(life->val, 8); // not_before
    *end_ts = read_be_uint(life->val + 8, 8); // not_after
    if (*start_ts > *end_ts) return false;
    return true;
}

static void enforce_lifetime_valid(const tlv* life) {
    // Exit with code 1 for invalid/expired cert, code 6 for malformed time inputs.
    uint64_t start_ts, end_ts;
    if (!parse_lifetime_window(life, &start_ts, &end_ts)) {
        fprintf(stderr, "Malformed lifetime field\n");
        exit(6);
    }

    uint64_t current_ts = (uint64_t) time(NULL);
    if (current_ts < start_ts || current_ts > end_ts) {
        fprintf(stderr, "Certificate expired or not valid yet\n");
        exit(1);
    }
}

void init_sec(int initial_state, char* peer_host, bool bad_mac) {
    state_sec = initial_state;
    hostname = peer_host;
    inc_mac = bad_mac;
    init_io();
    // Client side: load CA public key and prepare ephemeral keypair.
    // Server side: load certificate and prepare ephemeral keypair.
    if (initial_state == CLIENT_CLIENT_HELLO_SEND) { // client sends first message
        load_ca_public_key("ca_public_key.bin");
    } else if (initial_state == SERVER_CLIENT_HELLO_AWAIT) { // server awaits client message
        load_certificate("server_cert.bin");  
        load_private_key("server_key.bin"); 
    }
    generate_private_key();
    derive_public_key();
}

ssize_t input_sec(uint8_t* out_buf, size_t out_cap) {
    switch ( state_sec ) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        /* Version, Nonce, Public Key TLVs as its "value" */
        tlv* version_tlv = create_tlv(VERSION_TAG);
        uint8_t version_val = PROTOCOL_VERSION;
        add_val(version_tlv, &version_val, sizeof(version_val));

        tlv* nonce_tlv = create_tlv(NONCE);        
        generate_nonce(client_nonce, NONCE_SIZE); // fill nonce with 32 random bytes
        add_val(nonce_tlv, client_nonce, NONCE_SIZE);

        tlv* pubkey_tlv = create_tlv(PUBLIC_KEY); // public key TLV
        add_val(pubkey_tlv, public_key, pub_key_size); // public key set previously in init_sec() -> derive

        /* populate client_hello TLV  */
        client_hello = create_tlv(CLIENT_HELLO); // client hello TLV
        add_tlv(client_hello, version_tlv);
        add_tlv(client_hello, nonce_tlv);
        add_tlv(client_hello, pubkey_tlv);

        /* Serialize client_hello into out_buf */
        uint16_t len = serialize_tlv(out_buf, client_hello);
        if (len > out_cap) {
            fprintf(stderr, "CLIENT_HELLO exceeds output buffer capacity\n");
            exit(6);
        }

        free_tlv(client_hello); // client_hello not longer needed since serialization copies
        state_sec = CLIENT_SERVER_HELLO_AWAIT;

        return (ssize_t) len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        /* Nonce, Certificate, Public Key, Handshake Signature TLVs as its "value" */
        tlv* nonce_tlv = create_tlv(NONCE);
        generate_nonce(server_nonce, NONCE_SIZE); 
        add_val(nonce_tlv, server_nonce, NONCE_SIZE);

        tlv* cert_tlv = create_tlv(CERTIFICATE);
        add_val(cert_tlv, certificate, cert_size); // certificate generated in init_sec() -> load_certificate

        tlv* pubkey_tlv = create_tlv(PUBLIC_KEY);
        add_val(pubkey_tlv, public_key, pub_key_size); // public key set previously in init_sec() -> derive

        // Handshake signature -> concatenate client_hello and server_hello fields
        size_t sig_len = 0;
        uint8_t sig_buf[1024]; // buffer for serialized client_hello and server_hello

        sig_len += serialize_tlv(sig_buf, client_hello); // serialize client_hello into sig_buf
        sig_len += serialize_tlv(sig_buf + sig_len, nonce_tlv); // serialize server_hello fields into sig_buf
        sig_len += serialize_tlv(sig_buf + sig_len, pubkey_tlv);
        
        //  FROM README: The Server needs to switch between keys. It normally uses its Ephemeral Key (for deriving secrets), but temporarily needs its Identity Key (from server_key.bin) to sign the handshake.
        EVP_PKEY* priv_key = get_private_key(); // get ephemeral private key to save value
        
        load_private_key("server_key.bin"); // load server's private key for signing
        uint8_t signature[256];
        size_t signature_len = sign(signature, sig_buf, sig_len); // generate signature
        
        set_private_key(priv_key); // restore ephemeral private key since we loaded the server_key
        
        tlv* sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig_tlv, signature, signature_len);

        /* populate server_hello TLV */
        server_hello = create_tlv(SERVER_HELLO);
        add_tlv(server_hello, nonce_tlv);
        add_tlv(server_hello, cert_tlv);
        add_tlv(server_hello, pubkey_tlv);
        add_tlv(server_hello, sig_tlv);
        
        /* Serialize server_hello into out_buf */
        uint16_t len = serialize_tlv(out_buf, server_hello);
        if (len > out_cap) {
            fprintf(stderr, "SERVER_HELLO exceeds output buffer capacity\n");
            exit(6);
        }

        free_tlv(client_hello);
        free_tlv(server_hello); // server_hello not longer needed since serialization copies
        client_hello = NULL;
        server_hello = NULL;

        // derive secret and keys for encryption
        derive_secret();
        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        state_sec = DATA_STATE;

        return (ssize_t) len;
    }
    case DATA_STATE: {
        // TODO: read plaintext from stdin, encrypt it, compute MAC, serialize DATA TLV.
        // If `inc_mac` is true, intentionally corrupt the MAC for testing.
        // read input
        uint8_t plain_buf[1024];
        ssize_t plain_len = input_io(plain_buf, sizeof(plain_buf));
        if (plain_len <= 0) return 0;  // no data read

        // encrypt
        uint8_t iv_buf[IV_SIZE];
        uint8_t cipher_buf[1024];
        size_t cipher_len = encrypt_data(iv_buf, cipher_buf, plain_buf, (size_t)plain_len);

        tlv* iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv_buf, IV_SIZE);

        tlv* cipher_tlv = create_tlv(CIPHERTEXT);
        add_val(cipher_tlv, cipher_buf, cipher_len);

        // compute MAC over serialized IV and ciphertext
        uint8_t hmac_buf[1024];
        size_t hmac_buf_len = 0;
        hmac_buf_len += serialize_tlv(hmac_buf, iv_tlv);
        hmac_buf_len += serialize_tlv(hmac_buf + hmac_buf_len, cipher_tlv);

        uint8_t mac[MAC_SIZE];
        hmac(mac, hmac_buf, hmac_buf_len);

        // package DATA TLV
        tlv* mac_tlv = create_tlv(MAC);
        add_val(mac_tlv, mac, MAC_SIZE);
        
        tlv* data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, iv_tlv);
        add_tlv(data_tlv, mac_tlv);
        add_tlv(data_tlv, cipher_tlv);

        // send DATA TLV as output
        uint16_t len = serialize_tlv(out_buf, data_tlv);
        if (len > out_cap) {
            fprintf(stderr, "DATA exceeds output buffer capacity\n");
            exit(6);
        }

        free_tlv(data_tlv); 
           
        return (ssize_t) len;
    }
    default:
        // TODO: handle unexpected states.
        return (ssize_t) 0;
    }
}

void output_sec(uint8_t* in_buf, size_t in_len) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        print("RECV CLIENT HELLO");
        // TODO: parse CLIENT_HELLO, validate required fields and protocol version.
        // Load peer ephemeral key, store client nonce, and transition to SERVER_SERVER_HELLO_SEND.
        client_hello = deserialize_tlv(in_buf, in_len);
        if (client_hello == NULL || client_hello->type != CLIENT_HELLO) {
            fprintf(stderr, "Malformed CLIENT_HELLO\n");
            exit(6);
        }

        // validate version
        tlv* version_tlv = get_tlv(client_hello, VERSION_TAG);
        if (version_tlv == NULL || version_tlv->val[0] != PROTOCOL_VERSION) {
            fprintf(stderr, "Unsupported protocol version\n");
            exit(6);
        }
        // extract and save nonce
        tlv* nonce_tlv = get_tlv(client_hello, NONCE);
        if (nonce_tlv == NULL) {
            fprintf(stderr, "CLIENT_HELLO missing nonce\n");
            exit(6);
        }
        memcpy(client_nonce, nonce_tlv->val, NONCE_SIZE);
        // extract client's ephemeral public key 
        tlv* pubkey_tlv = get_tlv(client_hello, PUBLIC_KEY);
        if (pubkey_tlv == NULL) {
            fprintf(stderr, "CLIENT_HELLO missing public key\n");
            exit(6);
        }
        load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);

        state_sec = SERVER_SERVER_HELLO_SEND;

        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse SERVER_HELLO and verify certificate chain/lifetime/hostname.
        // Verify handshake signature, load server ephemeral key, derive keys, enter DATA_STATE.
        // Required exit codes: bad cert(1), bad identity(2), bad handshake sig(3), malformed(6).
        server_hello = deserialize_tlv(in_buf, in_len);
        if (server_hello == NULL || server_hello->type != SERVER_HELLO) {
            fprintf(stderr, "Malformed SERVER_HELLO\n");
            exit(6);
        }

        /* CHECK 1: verify certficate validity */
        tlv* cert_tlv = get_tlv(server_hello, CERTIFICATE);
        if (cert_tlv == NULL) {
            fprintf(stderr, "SERVER_HELLO missing certificate\n");
            exit(6);
        }

        
        tlv* DNS_tlv = get_tlv(cert_tlv, DNS_NAME);
        tlv* cert_pubkey_tlv = get_tlv(cert_tlv, PUBLIC_KEY);
        tlv* life_tlv = get_tlv(cert_tlv, LIFETIME);
        tlv* cert_sig_tlv = get_tlv(cert_tlv, SIGNATURE);
        if (DNS_tlv == NULL || cert_pubkey_tlv == NULL || life_tlv == NULL || cert_sig_tlv == NULL) {
            fprintf(stderr, "Malformed certificate in SERVER_HELLO\n");
            exit(6);
        }

        // recbuild certificate signature
        uint8_t cert_buf[1024];
        size_t cert_len = 0;
        cert_len += serialize_tlv(cert_buf, DNS_tlv);
        cert_len += serialize_tlv(cert_buf + cert_len, cert_pubkey_tlv);
        cert_len += serialize_tlv(cert_buf + cert_len, life_tlv);

        // verify certificate CA signature
        if(verify(cert_sig_tlv->val, cert_sig_tlv->length, cert_buf, cert_len, ec_ca_public_key) != 1) {
            fprintf(stderr, "Failed certificate signature verification\n");
            exit(1);
        }
        // verify certificate lifetime
        enforce_lifetime_valid(life_tlv);

        /* CHECK 2: verify identity */
        if (strncmp((char*) DNS_tlv->val, hostname, DNS_tlv->length) != 0) {
            fprintf(stderr, "DNS name does not match expected hostname\n");
            exit(2);
        }

        /* CHECK 3: verify handshake signature (server_hello's signature) */
        // parse nonce, public key, and signature TLVs from server_hello
        tlv* nonce_tlv = get_tlv(server_hello, NONCE);
        tlv* pubkey_tlv = get_tlv(server_hello, PUBLIC_KEY);
        tlv* sig_tlv = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
        if (nonce_tlv == NULL || pubkey_tlv == NULL || sig_tlv == NULL) {
            fprintf(stderr, "SERVER_HELLO missing fields for handshake signature verification\n");
            exit(6);
        }

        // reconstruct handshake signature
        size_t sig_len = 0;
        uint8_t sig_buf[1024];

        sig_len += serialize_tlv(sig_buf, client_hello);
        sig_len += serialize_tlv(sig_buf + sig_len, nonce_tlv);
        sig_len += serialize_tlv(sig_buf + sig_len, pubkey_tlv);

        // FROM README: key is the Server's Identity Key (found inside the Cert)
        // first load server identity key
        load_peer_public_key(cert_pubkey_tlv->val, cert_pubkey_tlv->length);
        if (verify(sig_tlv->val, sig_tlv->length, sig_buf, sig_len, ec_peer_public_key) != 1) {
            fprintf(stderr, "Failed handshake signature verification\n");
            exit(3);
        }

        // next, load server ephemeral key
        load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);
        
        // derive secret and keys for encryption
        derive_secret();
        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, nonce_tlv->val, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        free_tlv(client_hello);
        free_tlv(server_hello);
        client_hello = NULL;
        server_hello = NULL; 

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse DATA, verify MAC before decrypting, then output plaintext.
        // Required exit code: bad MAC(5), malformed(6).
        tlv*data_tlv = deserialize_tlv(in_buf, in_len);
        if (data_tlv == NULL || data_tlv->type != DATA) {
            fprintf(stderr, "Malformed DATA message\n");
            exit(6);
        }

        // extract IV, ciphertext, and MAC
        tlv* iv_tlv = get_tlv(data_tlv, IV);
        tlv* cipher_tlv = get_tlv(data_tlv, CIPHERTEXT);
        tlv* mac_tlv = get_tlv(data_tlv, MAC);
        if (iv_tlv == NULL || cipher_tlv == NULL || mac_tlv == NULL) {
            fprintf(stderr, "Malformed DATA\n");
            exit(6);
        }

        // reconstruct MAC and verify
        uint8_t hmac_buf[1024];
        size_t hmac_buf_len = 0;
        hmac_buf_len += serialize_tlv(hmac_buf, iv_tlv);
        hmac_buf_len += serialize_tlv(hmac_buf + hmac_buf_len, cipher_tlv);
        uint8_t mac[MAC_SIZE];
        hmac(mac, hmac_buf, hmac_buf_len);

        if(memcmp(mac, mac_tlv->val, MAC_SIZE) != 0) {
            fprintf(stderr, "Failed MAC verification\n");
            exit(5);
        }

        // decrypt and output plaintext
        uint8_t plain_buf[1024];
        size_t plain_len = decrypt_cipher(plain_buf, cipher_tlv->val, cipher_tlv->length, iv_tlv->val);
        output_io(plain_buf, plain_len);

        free_tlv(data_tlv);
        break;
    }
    default:
        // TODO: handle unexpected states.
        break;
    }
}
