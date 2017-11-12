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
    if(length < 1)
        return -1;
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

    // print log
    print_time();
    printf("command:read, filename:%s\n", filename);

    // send client confirmation of request
    char message[] = "You have chosen: read";
    char enc_msg[strlen(message)+BLOCK_SIZE];
    length = encrypt_text(message, strlen(message), enc_msg);
    int status = write_to_client(enc_msg, length, clientsocket);
    if(status < 1)
        return -1;

    // send client their file
    int send_status = send_file(filename);
    cerr << send_status << endl;

    // send client failure status or wait for
    // confirmation of success from client
    if(send_status < 0) {
        // if file does not exist
        char success[TOTAL_SIZE];
        memcpy(success, "Error", strlen("Error"));
        success[LENGTH_INDEX] = strlen("Error");
        // add DNE flag
        success[LAST_INDEX] = 2;
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, TOTAL_SIZE, enc_success);
        status = write_to_client(enc_success, length, clientsocket);
        if(status < 1)
            return -1;
        // print status
        print_time();
        cout << "status: fail - file does not exist" << endl;

    } else {
        // get success response back
        char * enc_text = (char *)malloc(RECEIVE_BUFFER);
        bzero(enc_text, RECEIVE_BUFFER);
        length = read_from_client(enc_text, RECEIVE_BUFFER, clientsocket);
        if(length < 1)
            return -1;
        char response_status[length+BLOCK_SIZE];
        length = decrypt_text(enc_text, length, response_status);
        free(enc_text);
        // print client status
        print_time();
        cout << "status: " << response_status << endl;
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

    // print log
    print_time();
    printf("command:write, filename:%s\n", filename);

    // send client confirmation of request
    char message[] = "You have chosen: write";
    char enc_msg[strlen(message)+BLOCK_SIZE];
    length = encrypt_text(message, strlen(message), enc_msg);
    int status = write_to_client(enc_msg, length, clientsocket);
    if(status < 1)
        return -1;

     // receive client file data
    int get_status = get_file(filename);

    // send client success status
    if(get_status < 0) {
        char success[TOTAL_SIZE];
        memcpy(success, "FAIL", strlen("FAIL"));
        success[LENGTH_INDEX] = strlen("FAIL");
        success[LAST_INDEX] = 3;
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, strlen(success), enc_success);
        status = write_to_client(enc_success, length, clientsocket);
        if(status < 1)
            return -1;
    } else {
        char success[TOTAL_SIZE];
        memcpy(success, "OK", strlen("OK"));
        success[LENGTH_INDEX] = strlen("OK");
        success[LAST_INDEX] = 1;
        char enc_success[TOTAL_SIZE+BLOCK_SIZE];
        length = encrypt_text(success, TOTAL_SIZE, enc_success);
        status = write_to_client(enc_success, length, clientsocket);
        if(status < 1)
            return -1;

        // print status
        print_time();
        printf("status: success\n");
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
    int status = write_to_client(enc_msg, length, clientsocket);
    if(status < 1)
        return -1;
    cerr << "Bad protocol message received" << endl;
    return 0;
}


