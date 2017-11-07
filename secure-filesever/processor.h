int server::process_client_request()
{
    int protocol = 0;
    char success[] = "You are authed\n";
    cout << "Sending success..." << endl;
    send_message_client(success, strlen(success), 0);
    // now read response
    char * response = (char *)malloc(128);
    bzero(response, 128);
    int length = read_from_client(response, 128, clientsocket);
    length = decrypt_text(response, length, 0);
    // get filename
    char filename[length];
    bzero(filename, length);
    // check read or write
    if(strncmp(response, "read ", strlen("read ")) == 0) {
        memcpy(filename, response+strlen("read "), length - strlen("read ")); // -1 for netcat newline
        cout << filename << endl;
        char message[] = "You have chosen: read\n";
        send_message_client(message, strlen(message), 0);
        send_file(filename, protocol);
    } else if(strncmp(response, "write ", strlen("write ")) == 0) {
        memcpy(filename, response+strlen("write "), length - strlen("write ")); // -1 for netcat newline
        char message[] = "You have chosen: write\n";
        send_message_client(message, strlen(message), 0);
        get_file(filename, protocol);
    } else {
        char message[] = "You have chosen: ERROR\n";
        send_message_client(message, strlen(message), 0);
        error("Bad protocol message received\n");
    }
    free(response);
    cout << "Done" << endl;
    return 0;
}

int server::send_message_client(char * message, int length, int protocol)
{
    int chunk_size = 16;
    int total_read = 0;
    int read;
    int end_flag;
    while(total_read < length) {
        char chunk[16];
        int remaining = length - total_read;
        // determine if end of data or not
        if(remaining > 14) {
            read = 14;
            end_flag = 0;
        } else {
            read = remaining;
            end_flag = 1;
        }
        // get data into array
        memcpy(chunk, message+total_read, read);
        total_read += read;
        // set flags
        chunk[14] = read;
        chunk[15] = end_flag;
        // encrypt then send chunk
        int length = encrypt_text(chunk, chunk_size, 0);
        write_to_client(chunk, length, clientsocket);
    }
    return 0;
}

int server::send_file(char * filename, int protocol)
{
    int chunk_size = 16;
    cout << "Sending file..." << endl;
    int file_size = get_filesize(filename);
    int total_read = 0;
    while(total_read < file_size) {
        char * file_contents = (char *) malloc(16);
        bzero(file_contents, 16);
        int read = get_file_128(filename, file_contents, total_read);
        int length = encrypt_text(file_contents, chunk_size, protocol);
        write_to_client(file_contents, length, clientsocket);
        total_read += read;
        free(file_contents);
    }
    // get client success
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
        if(response[15] == 1) {
            cout << "Detected last packet" << endl;
            length = write_file(filename, response, (int)response[14], total_written);
            cout << "Status: OK" << endl;
            break;
        } else {
            for(int i=0;i<14;i++)
                printf("%c", response[i]);
            printf("\n%d %d\n", response[14],response[15]);
        }
        // remove flags
        length -= 2;
        length = write_file(filename, response, length, total_written);
        total_written += length;
        free(response);
    }
    return 0;
}

int server::encrypt_text(char * text, int length, int protocol)
{
    int chunk_size = length;
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
