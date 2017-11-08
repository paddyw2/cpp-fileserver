int server::process_client_request()
{
    int protocol = 0;
    // now read response
    char * enc_text = (char *)malloc(128);
    bzero(enc_text, 128);
    int length = read_from_client(enc_text, 128, clientsocket);
    char response[length+434];
    length = decrypt_text(enc_text, length, 0, response);
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
        char enc_msg[strlen(message)+434];
        length = encrypt_text(message, strlen(message), 0, enc_msg);
        write_to_client(enc_msg, length, clientsocket);
        // send client their file
        int status = send_file(filename, protocol);
        if(status < 0) {
            // if file does not exist
            char success[TOTAL_SIZE];
            memcpy(success, "file not found", strlen("file not found"));
            success[LENGTH_INDEX] = strlen("file not found");
            success[LAST_INDEX] = 2;
            char enc_success[TOTAL_SIZE+434];
            length = encrypt_text(success, TOTAL_SIZE, 0, enc_success);
            write_to_client(enc_success, length, clientsocket);
            return 0;
        }
        // get success response back
        bzero(enc_text, 128);
        length = read_from_client(enc_text, 128, clientsocket);
        char response_status[length+434];
        length = decrypt_text(enc_text, length, 0, response_status);
        // print client status
        cerr << "Response: " << response_status << endl;
    } else if(strncmp(response, "write ", strlen("write ")) == 0) {
        // parse client request
        memcpy(filename, response+strlen("write "), length - strlen("write ")); // -1 for netcat newline
        // send client confirmation of request
        char message[] = "You have chosen: write";
        char enc_msg[strlen(message)+434];
        length = encrypt_text(message, strlen(message), 0, enc_msg);
        write_to_client(enc_msg, length, clientsocket);
        // receive client file data
        int status = get_file(filename, protocol);
        // send client success status
        if(status < 0) {
            char success[] = "FAIL";
            char enc_success[TOTAL_SIZE+434];
            length = encrypt_text(success, strlen(success), 0, enc_success);
            write_to_client(enc_success, length, clientsocket);
            cerr << "FAIL" << endl;
        } else {
            char success[] = "OK";
            char enc_success[TOTAL_SIZE+434];
            length = encrypt_text(success, strlen(success), 0, enc_success);
            write_to_client(enc_success, length, clientsocket);
            cerr << "Sent OK" << endl;
        }
    } else {
        char message[] = "You have chosen: ERROR";
        char enc_msg[strlen(message)+434];
        length = encrypt_text(message, strlen(message), 0, enc_msg);
        write_to_client(enc_msg, length, clientsocket);
        cerr << "Bad protocol message received" << endl;
    }
    free(enc_text);
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
        char enc_chunk[read + 434];
        int length = encrypt_text(file_contents, chunk_size, protocol, enc_chunk);
        write_to_client(enc_chunk, length, clientsocket);
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
        char plaintext[return_size];
        int length = decrypt_text(response, return_size, 0, plaintext);
        if(plaintext[LAST_INDEX] == 1) {
            // last packet detected
            length = write_file(filename, plaintext, (int)plaintext[LENGTH_INDEX], total_written);
            // check for file writing errors
            if(length < (int)plaintext[LENGTH_INDEX]) {
                status = -1;
                break;
            }
            // transmission OK
            break;
        }
        // remove flags
        length -= FLAG_SIZE;
        length = write_file(filename, plaintext, length, total_written);
        // check for file writing errors
        if(length < (int)plaintext[LENGTH_INDEX]) {
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
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        ciphertext_len = encryptor.encrypt((unsigned char *)plaintext, length, key, iv, (unsigned char *)ciphertext);
        cerr << "Cipher length: " << ciphertext_len << endl;
    }
    return ciphertext_len;
}

int server::decrypt_text(char * ciphertext, int length, int protocol, char * plaintext)
{
    int plaintext_len;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        plaintext_len = encryptor.decrypt((unsigned char *)ciphertext, length, key, iv, (unsigned char *)plaintext);
        cerr << "Decrypt length: " << plaintext_len << endl;
    }
    return plaintext_len;
}
