int server::process_client_request()
{
    int protocol = 0;
    char success[] = "You are authed\n";
    int length = encrypt_text(success, strlen(success), protocol);
    cout << "Sending success..." << endl;
    write_to_client(success, length, clientsocket);
    // now read response
    char * response = (char *)malloc(128);
    bzero(response, 128);
    length = read_from_client(response, 128, clientsocket);
    length = decrypt_text(response, length, 0);
    // get filename
    char filename[length];
    bzero(filename, length);
    // check read or write
    if(strncmp(response, "read ", strlen("read ")) == 0) {
        memcpy(filename, response+strlen("read "), length - strlen("read ")); // -1 for netcat newline
        cout << filename << endl;
        char message[] = "You have chosen: read\n";
        length = encrypt_text(message, strlen(message), 0);
        write_to_client(message, length, clientsocket);
        send_file(filename, protocol);
    } else if(strncmp(response, "write ", strlen("write ")) == 0) {
        memcpy(filename, response+strlen("write "), length - strlen("write ")); // -1 for netcat newline
        char message[] = "You have chosen: write\n";
        length = encrypt_text(message, strlen(message), 0);
        write_to_client(message, length, clientsocket);
        get_file(filename, protocol);
    } else {
        char message[] = "You have chosen: ERROR\n";
        length = encrypt_text(message, strlen(message), 0);
        write_to_client(message, length, clientsocket);
        error("Bad protocol message received\n");
    }
    free(response);
    cout << "Done" << endl;
    return 0;
}

int server::send_file(char * filename, int protocol)
{
    cout << "Sending file..." << endl;
    int file_size = get_filesize(filename);
    int total_read = 0;
    while(total_read < file_size) {
        char * file_contents = (char *) malloc(16);
        bzero(file_contents, 16);
        int read = get_file_128(filename, file_contents, total_read);
        int length = encrypt_text(file_contents, read, protocol);
        write_to_client(file_contents, length, clientsocket);
        total_read += read;
        free(file_contents);
    }
    char success[] = "---OK---";
    int length = encrypt_text(success, strlen(success), 0);
    write_to_client(success, length, clientsocket);
    return 0;
}

int server::get_file(char * filename, int protocol)
{
    cout << "Receiving file..." << endl;
    int return_size = 16;
    int total_written = 0;
    while(1) {
        char * response = (char *)malloc(16);
        return_size = read_from_client(response, 16, clientsocket);
        if(return_size <= 0) {
            cout << "Status: FAIL" << endl;
            break;
        }
        int length = decrypt_text(response, return_size, 0);
        if(strncmp(response, "---OK---", strlen("---OK---")) == 0) {
            cout << "Status: " << response << endl;
            break;
        }
        length = write_file(filename, response, length);
        total_written += length;
        free(response);
    }
    return 0;
}

int server::encrypt_text(char * text, int length, int protocol)
{
    int chunk_size = 16;
    if(protocol == 0) {
        // no encryption, print for logging purposes
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

int server::get_client_file_response()
{
    cout << "Receiving..." << endl;
    int return_size = 1;
    int counter = 0;
    while(return_size != 0) {
        char * response = (char *)malloc(16);
        return_size = read_from_client(response, 16, clientsocket);
        printf("Length=%d\n", return_size);
        for(int i=0;i<return_size;i++) {
            printf("%c", response[i]);
        }
        free(response);
        counter++;
    }
    printf("\n", counter);
    return 0;
}
