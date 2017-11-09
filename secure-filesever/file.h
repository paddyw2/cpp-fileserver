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
