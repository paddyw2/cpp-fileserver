int server::process_client_request()
{
    int protocol = 0;
    // now read response
    char * response = (char *)malloc(128);
    bzero(response, 128);
    int length = read_from_client(response, 128, clientsocket);
    if(length<0)
        return -1;
    /*
    char * decrypted_text = (char *)malloc(length);
    length = decrypt_text(response, length, 0, decrypt_text);
    free(decrypted_text);
    */
    // get filename
    char filename[length];
    bzero(filename, length);
    // check read or write
    if(strncmp(response, "read ", strlen("read ")) == 0) {
        // parse client request
        memcpy(filename, response+strlen("read "), length - strlen("read ")); // -1 for netcat newline
        // send client confirmation of request
        char * message = (char *)malloc(32);
        memcpy(message, "You have chosen: read", strlen("You have chosen: read"));
        write_to_client(message, length, clientsocket);
        /*
        char * encrypted_text = (char *)malloc(length+434);
        length = encrypt_text(message, strlen(message), 0, encrypted_text);
        write_to_client(encrypted_text, length, clientsocket);
        free(message);
        free(encrypted_text);
        */
        // send client their file
        int status = send_file(filename, protocol);
        if(status < 0) {
            // if file does not exist
            char * success = (char *)malloc(TOTAL_SIZE);
            memcpy(success, "file not found", DATA_SIZE);
            success[LENGTH_INDEX] = strlen("file not found");
            success[LAST_INDEX] = 2;
            write_to_client(success, length, clientsocket);
            /*
            encrypted_text = (char *)malloc(length+434);
            length = encrypt_text(success, TOTAL_SIZE, 0);
            write_to_client(encrypted_text, length, clientsocket);
            free(success);
            free(encrypted_text);
            */
            return 0;
        }
        // get success response back
        bzero(response, 128);
        length = read_from_client(response, 128, clientsocket);
        if(length<0)
            return -1;
        /*
        decrypted_text = (char *)malloc(length);
        length = decrypt_text(response, length, 0, decrypted_text);
        free(decrypted_text);
        */
        // print client status
    } else if(strncmp(response, "write ", strlen("write ")) == 0) {
        // parse client request
        memcpy(filename, response+strlen("write "), length - strlen("write ")); // -1 for netcat newline
        // send client confirmation of request
        char * message = (char *)malloc(32);
        memcpy(message, "You have chosen: write", strlen("You have chosen: write"));
        /*
        char * encrypted_text = (char *)malloc(length+434);
        length = encrypt_text(message, strlen(message), 0, encrypted_text);
        write_to_client(encrypted_text, length, clientsocket);
        */
        write_to_client(message, length, clientsocket);
        // receive client file data
        int status = get_file(filename, protocol);
        // send client success status
        free(message);
        if(status < 0) {
            char * success = (char *)malloc(TOTAL_SIZE);
            memcpy(success, "FAIL", strlen("FAIL"));
            /*
            encrypted_text = (char *)malloc(length+434);
            length = encrypt_text(success, strlen("FAIL"), 0, encrypted_text);
            write_to_client(encrypted_text, length, clientsocket);
            free(encrypted_text);
            */
            write_to_client(success, length, clientsocket);
            free(success);
            cerr << "FAIL" << endl;
        } else {
            char * success = (char *)malloc(TOTAL_SIZE);
            memcpy(success, "OK", strlen("OK"));
            /*
            encrypted_text = (char *)malloc(length+434);
            length = encrypt_text(success, strlen("OK"), 0, encrypted_text);
            write_to_client(success, length, clientsocket);
            cerr << "Sent OK" << endl;
            free(success);
            free(encrypted_text);
            */
            write_to_client(success, length, clientsocket);
            free(success);
            cerr << "OK" << endl;
        }
    } else {
        char * message = (char *)malloc(32);

        memcpy(message, "You have chosen: ERROR", strlen("You have chosen: ERROR"));
        /*
        char * encrypted_text = (char *)malloc(length+434);
        length = encrypt_text(message, strlen(message), 0, encrypted_text);
        write_to_client(encrypted_text, length, clientsocket);
        cerr << "Bad protocol message received" << endl;
        free(message);
        free(encrypted_text);
        */
        write_to_client(message, length, clientsocket);
        free(message);
        cerr << "Bad protocol message received" << endl;
    }
    free(response);
    cerr << "Finished client request" << endl;
    return 0;
}

int server::send_file(char * filename, int protocol)
{
    int status = 0;
    int chunk_size = TOTAL_SIZE;
    cerr << "Sending file..." << endl;
    int file_size = get_filesize(filename);
    // check for file errors
    if(file_size < 0)
        return -1;
    int total_read = 0;
    while(total_read < file_size) {
        char * file_contents = (char *) malloc(TOTAL_SIZE);
        bzero(file_contents, TOTAL_SIZE);
        int read = get_file_128(filename, file_contents, total_read);
        // check for file reading errors
        if(read < 0) {
            status = -1;
            break;
        }
        int length = encrypt_text(file_contents, chunk_size, protocol);
        write_to_client(file_contents, length, clientsocket);
        total_read += read;
        cerr << "Freeing 1" << endl;
        free(file_contents);
        cerr << "Freed 2" << endl;
    }
    // get client success
    return status;
}

int server::get_file(char * filename, int protocol)
{
    cerr << "Receiving file..." << endl;
    int status = 0;
    int return_size = TOTAL_SIZE;
    int total_written = 0;
    while(1) {
        char * response = (char *)malloc(TOTAL_SIZE);
        return_size = read_from_client(response, TOTAL_SIZE, clientsocket);
        if(return_size <= 0) {
            cerr << "Status: FAIL" << endl;
            status = -1;
            break;
        }
        int length = decrypt_text(response, return_size, 0);
        if(response[LAST_INDEX] == 1) {
            // last packet detected
            length = write_file(filename, response, (int)response[LENGTH_INDEX], total_written);
            // check for file writing errors
            if(length < (int)response[LENGTH_INDEX]) {
                status = -1;
                break;
            }
            // transmission OK
            break;
        }
        // remove flags
        length -= FLAG_SIZE;
        length = write_file(filename, response, length, total_written);
        // check for file writing errors
        if(length < (int)response[LENGTH_INDEX]) {
            status = -1;
            break;
        }
        total_written += length;
        free(response);
    }
    return status;
}

int server::encrypt_text(char * plaintext, int length, int protocol, char * ciphertext)
{
    int ciphertext_len;
    int block_size = 16;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        // make cipher text big enough to account for padding
        //unsigned char * ciphertext = (unsigned char *)malloc(length+block_size*2);
        ciphertext_len = encryptor.encrypt((unsigned char *)plaintext, length, key, iv, (unsigned char *)ciphertext);
        cerr << "Cipher length: " << ciphertext_len << endl;
        // resize input and copy result to memory location
    }
    return ciphertext_len;
}

int server::decrypt_text(char * encrypted_text, int length, int protocol, char * plaintext)
{
    int decrypt_len;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";

        // plaintext will be equal or less than cipher length
        // unsigned char * plaintext = (unsigned char *)malloc(length);
        // bzero(plaintext, length);
        decrypt_len = encryptor.decrypt((unsigned char *)encrypted_text, length, key, iv, (unsigned char *)plaintext);
        cerr << "Decrypt length: " << decrypt_len << endl;
        for(int i=0;i<decrypt_len;i++)
            cerr << plaintext[i];
        cerr << endl;
    }

    return decrypt_len;
}
