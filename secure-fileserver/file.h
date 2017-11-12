/*
 * Opens a file and reads a chunk of size determined
 * by the constants.h file, beginning at the position
 * indicated by the offset parameter
 * Returns the success status of the operation
 */
int server::get_file_128(char filename[], char * contents, int offset, FILE * fptr)
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

    // read file data into contents parameter
    int status = fread(contents, sizeof(char), chunk_size, fptr);
    // set appropriate flags indicating
    // the size of data read, and whether
    // or not it is the end of the file
    int sub_count = status;
    int index = 0;
    int max_num = 125;
    while(sub_count - max_num > 0) {
        sub_count -= max_num;
        contents[LENGTH_INDEX+index] = 125;
        contents[LENGTH_INDEX+index+1] = 0;
        index++;
    }
    contents[LENGTH_INDEX+index] = sub_count;
    contents[LAST_INDEX] = last;

    // success status
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
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "r");
    if(!fptr) {
        printf("File opening failed\n");
        exit(EXIT_FAILURE);
    }

    int status = 0;
    int chunk_size = TOTAL_SIZE;
    int file_size = get_filesize(filename);
    // check for file errors
    if(file_size < 0)
        return -1;
    int total_read = 0;
    while(total_read < file_size) {
        char * file_contents = (char *) malloc(TOTAL_SIZE);
        bzero(file_contents, TOTAL_SIZE);
        int read = get_file_128(filename, file_contents, total_read, fptr);
        // check for file reading errors
        if(read < 0) {
            status = -1;
            break;
        }
        char enc_chunk[TOTAL_SIZE + BLOCK_SIZE];
        int length = encrypt_text(file_contents, chunk_size, enc_chunk);
        int status = write_to_client(enc_chunk, length, clientsocket);
        if(status < 1)
            return -1;
        total_read += read;
        free(file_contents);
    }
    fclose(fptr);
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

    remove(filename);
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "a");

    if(!fptr) {
        //fptr = fopen(filename, "w");
        if(!fptr) {
            printf("File opening failed\n");
            exit(EXIT_FAILURE);
        }
    }

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
        if(return_size < 1) {
            // print status
            print_time();
            printf("status: fail - client disconnected\n");
            status = -1;
            break;
        } else if(return_size != encrypt_size) {
            // if full packet not received
            // fixes bad key error
            int subtotal = return_size;
            while(subtotal < ENCRYPTED_SIZE) {
                return_size = read_from_client(response+subtotal, encrypt_size-subtotal, clientsocket);
                subtotal += return_size;
            }
            return_size = subtotal;
            cerr << "Finally got: " << subtotal << " orig: " << ENCRYPTED_SIZE << endl;
        }
        // decrypt data block
        char plaintext[return_size];
        int length = decrypt_text(response, return_size, plaintext);

        // parse to check if it is the last block
        // to be received
        if(plaintext[LAST_INDEX] == 1) {
            // last packet detected
            length = get_data_length(plaintext);
            int orig_len = length;
            // write data to file
            length = fwrite(plaintext, sizeof(char), length, fptr);
            //length = write_file(filename, plaintext, length, total_written);
            // check for file writing errors
            if(length < orig_len) {
                status = -1;
                break;
            }
            // transmission OK
            break;
        } else {
            // remove flags to get only data
            length = get_data_length(plaintext);
            int orig_len = length;
            // write data to file
            length = fwrite(plaintext, sizeof(char), length, fptr);
            //length = write_file(filename, plaintext, length, total_written);
            // check for file writing errors
            if(length < orig_len) {
                status = -1;
                break;
            }
            // increment total written
            total_written += length;
        }
        free(response);
    }

    if(fclose(fptr) < 0) {
        print_time();
        printf("status: fail - disk space exceeded\n");
        remove(filename);
        status = -1;
    }
    return status;
}

int server::get_data_length(char * data)
{
    int max_num = 125;
    int current = (int)data[LENGTH_INDEX];
    int total = current;
    int index = 0;
    while(current == max_num) {
        index++;
        current = (int)data[LENGTH_INDEX+index];
        total += current;
    }
    return total;
}
