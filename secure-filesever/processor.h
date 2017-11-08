/*
 * Waits for a client request, and processes it
 * and sends it to the appropriate sub functions
 * Can be either read, write or bad request
 */
int server::process_client_request()
{
    // get client request
    char * enc_text = (char *)malloc(RECEIVE_BUFFER);
    bzero(enc_text, RECEIVE_BUFFER);
    int length = read_from_client(enc_text, RECEIVE_BUFFER, clientsocket);
    char response[length+BLOCK_SIZE];
    length = decrypt_text(enc_text, length, 0, response);
    free(enc_text);
    cerr << "Response: " << response << endl;
    // process client request
    if(strncmp(response, "read ", strlen("read ")) == 0) {
        process_read_request(response, length);
    } else if(strncmp(response, "write ", strlen("write ")) == 0) {
        process_write_request(response, length);
    } else {
        process_bad_request();
    }
    cerr << "Finished client request" << endl;
    return 0;
}

/*
 * Parses the client request based on the assumption
 * that it is requesting a file
 * Essentially extracts the requested filename and
 * calls the send file function
 * Sends the status of the function back to the client
 */
int server::process_read_request(char * response, int length)
{
    int protocol = 0;
    // send client confirmation of request
    char message[] = "You have chosen: read";
    char enc_msg[strlen(message)+BLOCK_SIZE];
    length = encrypt_text(message, strlen(message), 0, enc_msg);
    write_to_client(enc_msg, length, clientsocket);

    // extract filename
    char filename[length];
    bzero(filename, length);
    memcpy(filename, response+strlen("read "), length - strlen("read "));

    // send client their file
    int status = send_file(filename, protocol);

    // send client failure status or wait for
    // confirmation of success from client
    if(status < 0) {
        // if file does not exist
        char success[TOTAL_SIZE];
        memcpy(success, "file not found", strlen("file not found"));
        success[LENGTH_INDEX] = strlen("file not found");
        success[LAST_INDEX] = 2;
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, TOTAL_SIZE, 0, enc_success);
        write_to_client(enc_success, length, clientsocket);
    } else {
        // get success response back
        char * enc_text = (char *)malloc(RECEIVE_BUFFER);
        bzero(enc_text, RECEIVE_BUFFER);
        length = read_from_client(enc_text, RECEIVE_BUFFER, clientsocket);
        char response_status[length+BLOCK_SIZE];
        length = decrypt_text(enc_text, length, 0, response_status);
        free(enc_text);
        // print client status
        cerr << "Response: " << response_status << endl;
    }
    return 0;
}

/*
 * Parses the client request based on the assumption
 * that it is sending a file
 * Essentially extracts the destination filename and
 * calls the get file function
 * Sends the status of the function back to the client
 */
int server::process_write_request(char * response, int length)
{
    int protocol = 0;
    // send client confirmation of request
    char message[] = "You have chosen: write";
    char enc_msg[strlen(message)+BLOCK_SIZE];
    length = encrypt_text(message, strlen(message), 0, enc_msg);
    write_to_client(enc_msg, length, clientsocket);

    // extract filename
    char filename[length];
    bzero(filename, length);
    memcpy(filename, response+strlen("write "), length - strlen("write "));

     // receive client file data
    int status = get_file(filename, protocol);

    // send client success status
    if(status < 0) {
        char success[] = "FAIL";
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, strlen(success), 0, enc_success);
        write_to_client(enc_success, length, clientsocket);
        cerr << "FAIL" << endl;
    } else {
        char success[] = "OK";
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, strlen(success), 0, enc_success);
        write_to_client(enc_success, length, clientsocket);
        cerr << "Sent OK" << endl;
    }
    return 0;
}

/*
 * Sends the client a bad request
 * error message
 */
int server::process_bad_request()
{
    char message[] = "You have chosen: ERROR";
    char enc_msg[strlen(message)+BLOCK_SIZE];
    int length = encrypt_text(message, strlen(message), 0, enc_msg);
    write_to_client(enc_msg, length, clientsocket);
    cerr << "Bad protocol message received" << endl;
    return 0;
}

/*
 * Tries to send the specified filename in encrypted
 * chunks using the specified protocol
 * Returns the success or failure of the function
 */
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
        char enc_chunk[read + BLOCK_SIZE];
        int length = encrypt_text(file_contents, chunk_size, protocol, enc_chunk);
        write_to_client(enc_chunk, length, clientsocket);
        total_read += read;
        free(file_contents);
    }
    // get client success
    return status;
}

/*
 * Tries to get the specified filename and send in
 * encrypted chunks to the client
 * Returns the success or failure of the function
 */
int server::get_file(char * filename, int protocol)
{
    cerr << "Receiving file..." << endl;
    int status = 0;
    int return_size = ENCRYPTED_SIZE;
    int total_written = 0;
    while(1) {
        // get block of encrypted data from client
        char * response = (char *)malloc(ENCRYPTED_SIZE);
        return_size = read_from_client(response, ENCRYPTED_SIZE, clientsocket);
        // check for read errors
        if(return_size <= 0) {
            cerr << "Status: FAIL" << endl;
            status = -1;
            break;
        }

        // decrypt data block
        char plaintext[return_size];
        int length = decrypt_text(response, return_size, 0, plaintext);

        // parse to check if it is the last block
        // to be received
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
        } else {
            // remove flags to get only data
            length -= FLAG_SIZE;
            // write data to file
            length = write_file(filename, plaintext, length, total_written);
            // check for file writing errors
            if(length < (int)plaintext[LENGTH_INDEX]) {
                status = -1;
                break;
            }
            // increment total written
            total_written += length;
            free(response);
        }
    }
    return status;
}
