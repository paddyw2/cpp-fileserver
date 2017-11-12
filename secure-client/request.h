/*
 * Sends a request in the format:
 * [read || write] [filename]
 * to the server and process
 * server response
 */
int client::make_request()
{
    // contains main program logic
    // checks for read or write command
    // then send appropriate protocol messages

    // get specific command (read or write)
    char command[10];
    bzero(command, 10);
    memcpy(command, arg_command, strlen("write "));

    // formulate request of format: write [filename]
    int space_len = 1;
    int null_term = 1;
    int message_len = strlen(command)+strlen(arg_filename)+space_len+null_term;
    char message[message_len];
    bzero(message, message_len);

    // concatenate strings
    memcpy(message, command, strlen(command));
    message[strlen(command)] = ' ';
    memcpy(message+strlen(command)+space_len, arg_filename, strlen(arg_filename));

    // encrypt message and send to sever
    char enc_msg[message_len+BLOCK_SIZE];
    int length = encrypt_text(message, strlen(message), enc_msg);
    write_to_server(enc_msg, length);

    // get acknowledgment back from server
    char * response = (char *)malloc(RECEIVE_BUFFER);
    length = read_from_server(response, RECEIVE_BUFFER);
    char plaintext[length];
    length = decrypt_text(response, length, plaintext);

    if(strncmp(command, "read", 4) == 0) {
        // now output server response to stdout
        int status = get_server_response();

        // now send success message back
        if(status < 0) {
            char success[] = "FAIL";
            char enc_success[strlen("FAIL")+BLOCK_SIZE];
            length = encrypt_text(success, strlen(success), enc_success);
            write_to_server(enc_success, length);
        } else {
            char success[] = "success";
            char enc_success[strlen(success)+1+BLOCK_SIZE];
            length = encrypt_text(success, strlen(success)+1, enc_success);
            write_to_server(enc_success, length);
            cerr << "OK" << endl;
        }
    } else {
        // now send stdin to server
        send_stdin(arg_filename);

        // now get server success message back
        bzero(response, RECEIVE_BUFFER);
        length = read_from_server(response, RECEIVE_BUFFER);
        char plain_res[length];
        length = decrypt_text(response, length, plain_res);
        if(plain_res[LAST_INDEX] < 2)
            cerr << "OK" << endl;
        else
            cerr << "Error: file could not be written" << endl;
    }
    return 0;
}
