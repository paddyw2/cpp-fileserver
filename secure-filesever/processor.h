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
    length = decrypt_text(enc_text, length, response);
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
    // extract filename
    char filename[length];
    bzero(filename, length);
    memcpy(filename, response+strlen("read "), length - strlen("read "));

    // send client confirmation of request
    char message[] = "You have chosen: read";
    char enc_msg[strlen(message)+BLOCK_SIZE];
    length = encrypt_text(message, strlen(message), enc_msg);
    write_to_client(enc_msg, length, clientsocket);

    // send client their file
    int status = send_file(filename);

    // send client failure status or wait for
    // confirmation of success from client
    if(status < 0) {
        // if file does not exist
        char success[TOTAL_SIZE];
        memcpy(success, "file not found", strlen("file not found"));
        success[LENGTH_INDEX] = strlen("file not found");
        success[LAST_INDEX] = 2;
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, TOTAL_SIZE, enc_success);
        write_to_client(enc_success, length, clientsocket);
    } else {
        // get success response back
        char * enc_text = (char *)malloc(RECEIVE_BUFFER);
        bzero(enc_text, RECEIVE_BUFFER);
        length = read_from_client(enc_text, RECEIVE_BUFFER, clientsocket);
        char response_status[length+BLOCK_SIZE];
        length = decrypt_text(enc_text, length, response_status);
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
    // extract filename
    char filename[length];
    bzero(filename, length);
    memcpy(filename, response+strlen("write "), length - strlen("write "));

    // send client confirmation of request
    char message[] = "You have chosen: write";
    char enc_msg[strlen(message)+BLOCK_SIZE];
    length = encrypt_text(message, strlen(message), enc_msg);
    write_to_client(enc_msg, length, clientsocket);

     // receive client file data
    int status = get_file(filename);

    // send client success status
    if(status < 0) {
        char success[] = "FAIL";
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, strlen(success), enc_success);
        write_to_client(enc_success, length, clientsocket);
        cerr << "FAIL" << endl;
    } else {
        char success[] = "OK";
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, strlen(success), enc_success);
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
    int length = encrypt_text(message, strlen(message), enc_msg);
    write_to_client(enc_msg, length, clientsocket);
    cerr << "Bad protocol message received" << endl;
    return 0;
}


