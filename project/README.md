# CS 118 Winter 26 Project 2
Modularization: 
client:  starts with state client_client_hello_send -> client_server_hello_await waits for servers response and verifies -> can send encrypted data or receive and decrypt data
server: starts with state server_client_hello_await -> server_server_hello_send verifies the client_hello then sends back server response -> can send encrypted data or receive and decrypt data

# Helper functions
We started with implementing the helper functions read_be_uint, parse_lifetime_window, and enforce_lifetime_valid. 

read_be_uint:
This function converts an n-byte big-endian sequence to a 64-bit integer.

parse_lifetime_window:
Following the tlv struct given in consts.h, this function simply ensures that all fields of the struct are valid. Additionally, the data is parsed using read_be_uint to populate the parameter addresses start_ts and end_ts.

enforce_lifetime_valid:
Using parse_lifetime_window, we used the pass in life parameter and extract the certificate lifetime's start and end time. Then, by using the function time(NULL), which gets the current time, checks if it falls inside the bounds of start and end. Falling outside exits with code 6.

# init_sec
This function mostly just populates the global parameters in security.c (state_sec, hostname, inc_mac). We use init_io to initialize the IO layer, then generate the keys. This would be done by first determining the host's identity using the initial state (client_send or server_await). For clients, they first load in their ca_public_key, which is used for the certificate validation. For servers, they load in the server certificate (used for identity validation). Both hosts then generate a private key and derive their public key via that private key (the ephemeral keys).

# input_sec
Input_sec is modularized into three parts: CLIENT_CLIENT_HELLO_SEND, SERVER_SERVER_HELLO_SEND, and DATA_STATE.

- CCHS: In this state, the client is sending the inital hello message.
We start by forming the version, nonce, and public key tlv's, which will be added to the client_hello tlv (the packet to be sent out). create_tlv(TLV_TYPE), then add_val(tlv, val, val_size) is typically the procedure to forming the tlv's. The nonces (both client and server) will be stored as a global variable since the host will need to remember both when creating the secret key. The hosts' public keys are stored as global variables in libsecurity.h (loaded in by derive_public_key()). To form the client_hello, we simply create the tlv and add in the other 3 tlv's as values (add_val(parent_tlv, child_tlv)). This client_hello tlv is also stored as a global variable, being saved for server signature verification. Finally, we serialize the client_hello tlv into the out_buf to send out to server, and check to make sure it doesn't exceed the buffer length (serialize returns the length). Upon sending the hello, client changes state to CLIENT_SERVER_HELLO_AWAIT, which waits for the server's response and verifies its identity and validity.

- SSHS: In this state, server (having received the client's message), sends its hello response.
Similar to CCHS, we start with forming the child tlv's. Server uses nonce, certificate, public key, and signature as its "hello data." Forming the nonce and public key tlv's follow the same procedure, with server creating and populaing its own server_nonce global-variable to send. The certificate tlv is formed similarly, with the value coming from the global variable in libsecurity.h, loaded in through init_sec. The handshake signature value should contain data from both client_hello and server_hello. Thus, we serialize client_hello tlv (saved in server host after receving and parsing it in SERVER_CLIENT_HELLO_AWAIT), the server's nonce tlv, and the server's public_key tlv into a sig_buffer. Before signing this buffer, however, we must switch to the server identity private key. This is because the ephemeral private key is used for creating/deriving the secret key, but signing the signature requires the server's identity private key. Before signing, we save the ephemeral key in a temporary EVP_PKEY*, and load in the server identity key. The sig_buffer is then signed, with the resulting value being placed in another buffer we call signature (sign() returns the signature length). After setting the global private key back to the ephemeral key, we create the signature tlv and form the server_hello tlv by adding the nonce, certificate, public_key, and signature tlv's into the data. We then serialize the server_hello into out_buf to send back to client. Finally, we derive the secret key using the client's public key and server's private key, along with the salt, which is formed by concatenating the client and servers' nonces. The secret key and salt are then used to derive the encryption and mac key.

- DATA_STATE: In this state, we have confirmed a valid connection between the hosts, and can freely input/send data.
In data state, we need to encrypt the input data, extracting the IV and ciphertext. We then use HMAC on the two to create the MAC to send. We start with filling a buffer using input_io(). Then, we use the encrypt_data() function, which first generates a nonce (IV) and then uses the enc_key to create the ciphertext. [The IV is a nonce that is meant to create a unique mac even for multiple instances of the same data/ciphertext]. Then, with the IV and ciphertext tlv's formed, we serialize this into a buffer and pass that into the hmac function. This generates our MAC, which we can then add into a tlv. Our final data_tlv is formed by adding the iv_tlv, cipher_tlv, and mac_tlv into its data field. Finally, we serialize this data_tlv and pass that into the out_buf (to send to the receiving host).

# output_sec
Output_sec is modularized into three parts: SERVER_CLIENT_HELLO_AWAIT, CLIENT_SERVER_HELLO_AWAIT, and DATA_STATE.

- SCHA: In this state, the server has just received the client_hello message and extracts the nonce and server public key.
This is the inital state for the server. Deserializing the data in the in_buf gives us the client_hello tlv, which is stored in the global variable (save for handshake signature). Additionally, we also need to extract the client's nonce and store it into the global variable, as well as its public key, which is loaded into the libsecurity.h using load_peer_public_key(). We also validate the existence of all of the listed tlv's and the client_hello protocol version. State is then changed to SERVER_SERVER_HELLO_SEND to send client the response.

- CSHA: In this state, client has just received the server's hello response message.
After deserializing and extracting the server_hello message (in the same manner as SCHA), we need to parse through all of its data to validate the server's certificate, identity and handshake signature. 
1. Certificate: The idae of this step is to use the data fields in the certificate to recreate the certificate signature and compare it to the original certificate's signature. As such, we extract dns name, public key, lifetime and cert_signature tlv's from the certificate tlv. To form the signature, we add the serialized dns_tlv, cert_public_key_tlv (certificate CA public key) , and lifetime_tlv into a buffer, the use the verify() function to compare our formed signature and the new signature. Additionally, we also need to enforce the lifetime after extracting it, using our helper function enforce_lifetime_tlv().
2. Identity: For identity, we simply need to compare the data of our saved hostname (loaded in from init_sec) and the dns tlv's data field. 
3. Handshake signature: For signature, we extract the server nonce, server ephemeral key, and signature tlv's from the server_hello. Using our saved client_hello (back when we first sent the initial client hello), we recreate the signature by serializing the client_hello, nonce, and pubkey tlv's into a new signature_buffer. Before verifying our newly created signature and received signature, we also must set the ec_peer_public_key as the server certificate's public key (extracted from the certificate tlv -> cert_pubkey tlv). 

After the 3 verifications, we set the ec_peer_public_key to the server's ephemeral key (extracted from pubkey tlv), and also extract the server nonce from the nonce tlv. Finally, we use the client private key and server public key to derive our secrete key, and create the salt by concatenating the nonces. Finally, we derive the encryptment and mac key (same keys as server).

- DATA_STATE: In this state, we have confirmed a valid connection between the hosts, and can freely receive data (to decrypt).
The input_buffer gives us data_tlv, where we extract the IV, ciphertext, and MAC. Before decrypting anything, we first reconstruct the MAC by adding the serialized IV and ciphertext tlv and pass it through the hmac function. We then use memcmp() with the reconstructed mac and the data field from the MAC tlv. Once validation is done, we can simply decrypt the ciphertext data into a plaintext buffer. The decrypt() function uses the ciphertext and IV, as well as the saved enc_key. Finally, we use output_io() to write out the resulting plain text.