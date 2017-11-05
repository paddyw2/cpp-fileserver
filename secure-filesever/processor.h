int server::process_client_request()
{
    int protocol = 0;
    char success[] = "Success";
    int length = encrypt_text(success, strlen(success), protocol);
    cout << "Sending..." << endl;
    write_to_client(success, length, clientsockfd);
    // now read response
    get_client_response();
    // process response (assume file request)
    char filename[] = "test.txt";
    send_file(filename, protocol);
    return 0;
}

int server::send_file(char * filename, int protocol)
{
    int file_size = get_filesize(filename);
    int total_read = 0;
    while(total_read < file_size) {
        char * file_contents = (char *) malloc(16);
        int read = get_file_128(filename, file_contents, total_read);
        int length = encrypt_text(file_contents, read, protocol);
        write_to_client(file_contents, length, clientsockfd);
        total_read += read;
        free(file_contents);
    }
    return 0;
}

int server::encrypt_text(char * text, int length, int protocol)
{
    if(protocol == 0) {
        // no encryption, print for logging purposes
        for(int i=0;i<length;i++) {
            printf("%c", text[i]);
        }
        printf("\n");
    }
    return length;
}

int server::decrypt_text(char * text, int length, int protocol)
{
    return length;
}

int server::get_client_response()
{
    cout << "Receiving..." << endl;
    int return_size = 1;
    while(return_size != 0) {
        char * response = (char *)malloc(16);
        return_size = read_from_client(response, 16, clientsockfd);
        for(int i=0;i<return_size;i++) {
            printf("%c", response[i]);
        }
        free(response);
    }
    return 0;
}
