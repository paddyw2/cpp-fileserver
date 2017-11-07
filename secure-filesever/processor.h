int server::process_client_request()
{
    int protocol = 0;
    // now read response
    char * response = (char *)malloc(128);
    bzero(response, 128);
    int length = read_from_client(response, 128, clientsocket);
    length = decrypt_text(response, length, 0);
    cerr << "Response: " << response << endl;
    // get filename
    char filename[length];
    bzero(filename, length);
    // check read or write
    if(strncmp(response, "read ", strlen("read ")) == 0) {
        // parse client request
        memcpy(filename, response+strlen("read "), length - strlen("read ")); // -1 for netcat newline
        // send client confirmation of request
        char message[] = "You have chosen: read";
        length = encrypt_text(message, strlen(message), 0);
        write_to_client(message, length, clientsocket);
        // send client their file
        int status = send_file(filename, protocol);
        if(status < 0) {
            // if file does not exist
            char success[TOTAL_SIZE];
            memcpy(success, "file not found", strlen("file not found"));
            success[LENGTH_INDEX] = strlen("file not found");
            success[LAST_INDEX] = 2;
            length = encrypt_text(success, TOTAL_SIZE, 0);
            write_to_client(success, length, clientsocket);
            return 0;
        }
        // get success response back
        bzero(response, 128);
        length = read_from_client(response, 128, clientsocket);
        length = decrypt_text(response, length, 0);
        // print client status
        cerr << "Response: " << response << endl;
    } else if(strncmp(response, "write ", strlen("write ")) == 0) {
        // parse client request
        memcpy(filename, response+strlen("write "), length - strlen("write ")); // -1 for netcat newline
        // send client confirmation of request
        char message[] = "You have chosen: write";
        length = encrypt_text(message, strlen(message), 0);
        write_to_client(message, length, clientsocket);
        // receive client file data
        int status = get_file(filename, protocol);
        // send client success status
        if(status < 0) {
            char success[] = "FAIL";
            length = encrypt_text(success, strlen(success), 0);
            write_to_client(success, length, clientsocket);
            cerr << "FAIL" << endl;
        } else {
            char success[] = "OK";
            length = encrypt_text(success, strlen(success), 0);
            write_to_client(success, length, clientsocket);
            cerr << "Sent OK" << endl;
        }
    } else {
        char message[] = "You have chosen: ERROR";
        length = encrypt_text(message, strlen(message), 0);
        write_to_client(message, length, clientsocket);
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
        free(file_contents);
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

int server::encrypt_text(char * text, int length, int protocol)
{
    int chunk_size = length;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        unsigned char * ciphertext = (unsigned char *)malloc(3*length);
        int ciphertext_len = encryptor.encrypt((unsigned char *)text, length, key, iv, ciphertext);
        cerr << "Cipher length: " << ciphertext_len << endl;
        unsigned char * plaintext = (unsigned char *)malloc(ciphertext_len);
        int decrypt_len = encryptor.decrypt(ciphertext, ciphertext_len, key, iv, plaintext);
        cerr << "Decrypt length: " << decrypt_len << endl;
        int fail = 0;
        for(int i=0;i<decrypt_len;i++) {
            if(plaintext[i] != text[i]) {
                fail = 1;
                break;
            }
        }
        if(fail == 0)
            cerr << "The same!" << endl;
        else
            cerr << "Decryption failed :(" << endl;
        free(ciphertext);
        free(plaintext);
    }
    return chunk_size;
}

int server::decrypt_text(char * text, int length, int protocol)
{
    if(protocol == 0) {
        // no encryption, print for logging purposes
    }
    return length;
}
