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
    char * response = (char *)malloc(128);
    length = read_from_server(response, 128);
    char plaintext[length];
    length = decrypt_text(response, length, plaintext);

    if(strncmp(command, "read ", strlen("read ") == 0)) {
        // now output server response to stdout
        int status = get_server_response();

        // now send success message back
        if(status < 0) {
            char success[] = "FAIL";
            char enc_success[strlen("FAIL")+BLOCK_SIZE];
            length = encrypt_text(success, strlen(success), enc_success);
            write_to_server(enc_success, length);
            cerr << "FAIL" << endl;
        } else {
            char success[] = "OK";
            char enc_success[strlen("OK")+BLOCK_SIZE];
            length = encrypt_text(success, strlen(success), enc_success);
            write_to_server(enc_success, length);
            cerr << "Sent OK" << endl;
        }
    } else {
        // now send stdin to server
        send_stdin(arg_filename);

        // now get server success message back
        bzero(response, 128);
        length = read_from_server(response, 128);
        char plain_res[length];
        length = decrypt_text(response, length, plain_res);
        plain_res[length+1] = 0;
        cerr << "Server status: " << plain_res << endl;
    }
    return 0;
}
