/*
 * Opens a file and reads a chunk of size determined
 * by the constants.h file, beginning at the position
 * indicated by the offset parameter
 * Returns the success status of the operation
 */
int server::get_file_128(char filename[], char * contents, int offset)
{
    int chunk_size;
    int last = 0;

    // check if there are 16bytes left in file
    int filesize = get_filesize(filename);
    if(filesize < 0)
        return -1;

    // calculate the size of chunk to read
    int remaining = filesize - offset;
    if(remaining > DATA_SIZE) {
        chunk_size = DATA_SIZE;
    } else {
        chunk_size = remaining;
        last = 1;
    }

    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "r");
    if(!fptr) {
        printf("File opening failed\n");
        exit(EXIT_FAILURE);
    }
    
    // seek to the offset position in the file
    fseek(fptr, offset, SEEK_SET);

    // read file data into contents parameter
    int status = fread(contents, sizeof(char), chunk_size, fptr);
    // set appropriate flags indicating
    // the size of data read, and whether
    // or not it is the end of the file
    contents[LENGTH_INDEX] = chunk_size;
    contents[LAST_INDEX] = last;

    // close file and return
    // success status
    fclose(fptr);
    return status;
}

/*
 * Writes length amount of data from the contents location
 * to a file of name filename
 * Uses the total_written variable to determine whether to
 * append or create a new file
 * Returns the success status of the function
 */
int server::write_file(char filename[], char * contents, int length, int total_written)
{
    int status;
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "a");

    if(!fptr || total_written == 0) {
        if(total_written == 0)
            fclose(fptr);
        fptr = fopen(filename, "w");
        if(!fptr) {
            printf("File opening failed\n");
            exit(EXIT_FAILURE);
        }
    }
    // use size to allocate memory to
    // file buffer
    status = fwrite(contents, sizeof(char), length, fptr);
    // close file
    fclose(fptr);
    return status;
}

/*
 * Returns the filesize of the specified
 * filename
 * If an error occurs, returns -1
 */
int server::get_filesize(char filename[])
{
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "r");
    if(!fptr) {
        return -1;
    }
    fseek(fptr, 0, SEEK_END);
    int sz = ftell(fptr);
    fclose(fptr);
    return sz;
}

/*
 * Tries to send the specified filename in encrypted
 * chunks using the specified protocol
 * Returns the success or failure of the function
 */
int server::send_file(char * filename)
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
        char enc_chunk[TOTAL_SIZE + BLOCK_SIZE];
        int length = encrypt_text(file_contents, chunk_size, enc_chunk);
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
int server::get_file(char * filename)
{
    cerr << "Receiving file..." << endl;
    int status = 0;
    // calculate size to read
    int encrypt_size = ENCRYPTED_SIZE;
    if(strncmp(cipher, "null", strlen("null")) == 0)
        encrypt_size = TOTAL_SIZE;

    int return_size = encrypt_size;
    int total_written = 0;
    while(1) {
        // get block of encrypted data from client
        char * response = (char *)malloc(encrypt_size);
        return_size = read_from_client(response, encrypt_size, clientsocket);
        // check for read errors
        if(return_size == 0) {
            cerr << "Status: FAIL" << endl;
            status = -1;
            break;
        }
        // decrypt data block
        char plaintext[return_size];
        int length = decrypt_text(response, return_size, plaintext);

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
        }
        free(response);
    }
    return status;
}
