/*
 * Receives the nonce and cipher from
 * client, and sends challenge to client
 * It then checks if the clients response
 * is correct, and if so, returns 0 for
 * authenticated
 * If not authenticated, returns -1
 */
int server::authenticate_client()
{
    // get nonce and cipher from client
    // and save to class variable
    int success = get_nonce_cipher();
    if(success < 0)
        return success;

    set_key_iv();

    // send a random challenge and check
    // client response is correct
    success = send_and_check_challenge();

    // indicate success status to client
    if(success == 1) {
        cerr << "Client authentication failed" << endl;
        print_time();
        cout << "status: fail - bad key" << endl;
        return -1;
    } else {
        cerr << "Client authenticated" << endl;
        char success[] = "You are authed\n";
        cerr << "Sending success..." << endl;
        char enc_success[strlen(success)+BLOCK_SIZE];
        int length = encrypt_text(success, strlen(success), enc_success);
        int status = write_to_client(enc_success, length, clientsocket);
        if(status < 1)
            return -1;
    }
    // indicate authentication successfull
    return 0;
}

/*
 * Waits for message from client and parses
 * this message to extract a cipher and nonce
 * These are then saved to class variables
 */
int server::get_nonce_cipher()
{
    // get plaintext nonce cipher message
    char * cipher_nonce = (char *) calloc(RECEIVE_BUFFER, sizeof(char));
    int return_size = read_from_client(cipher_nonce, RECEIVE_BUFFER-1, clientsocket);
    if(return_size < 1)
        return -1;
    // parse and extract nonce and cipher
    // information from message
    // extract cipher
    int index = 0;
    while(cipher_nonce[index] != ' ') {
        cipher[index] = cipher_nonce[index];
        printf("%c", cipher[index]);
        index++;
        if(index >= 31) {
            cerr << "Bad cipher" << endl;
            return -1;
        }
    }
    printf("\n");
    cipher[index] = 0;
    // now extract nonce
    print_time();
    cout << "nonce=";
    index++;
    int new_index = 0;
    while(index < return_size) {
        nonce[new_index] = cipher_nonce[index];
        printf("%0.2x", (unsigned char)nonce[new_index]);
        index++;
        new_index++;
        if(new_index >= 31) {
            cerr << "Bad nonce" << endl;
            return -1;
        }
    }
    printf("\n");
    // extraction successful
    nonce_length = new_index;
    free(cipher_nonce);
    return 0;
}

/*
 * Generates a random challenge and 
 * sends it to the client
 * It then waits for a response from
 * the client
 * It then checks this response is correct
 * Response should be:
 * sha256(password | challenge)
 */
int server::send_and_check_challenge()
{
    // generate random number
    int rand_size = 64;
    unsigned char *rand_challenge = (unsigned char *)calloc(rand_size, sizeof(unsigned char));
    if (!RAND_bytes(rand_challenge, rand_size)) {
        printf("Challenge generation error");
        exit(EXIT_FAILURE);
    }

    // send random number to client as challenge
    char enc_challenge[rand_size+BLOCK_SIZE];
    int length = encrypt_text((char *)rand_challenge, rand_size, enc_challenge);
    int status = write_to_client(enc_challenge, length, clientsocket);
    if(status < 1)
        return 1;
    // read their response
    char * chal_response = (char *) calloc(DIGESTSIZE+BLOCK_SIZE, sizeof(char));
    int return_size = read_from_client(chal_response, DIGESTSIZE+BLOCK_SIZE, clientsocket);
    if(return_size == 0)
        return 1;
    char plain_response[return_size];
    length = decrypt_text(chal_response, return_size, plain_response);

    // concatenate password with challenge
    char * concat = (char *) calloc(rand_size + strlen(password), sizeof(char));
    memcpy(concat, password, strlen(password));
    memcpy(concat+strlen(password), rand_challenge, rand_size);

    // calcualte hash of concatenation
    unsigned char digest[DIGESTSIZE];
    encryption encryptor;
    encryptor.get_SHA256((unsigned char *)concat, rand_size + strlen(password), digest);
    free(concat);

    // compare result with client response
    int success = 0;
    for(int i=0; i<DIGESTSIZE;i++) {
        if(digest[i] != (unsigned char)plain_response[i])
            success = 1;
    }

    return success;
}
