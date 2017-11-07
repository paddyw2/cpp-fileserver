/*
 * opens a file in the current directoy by name
 * and returns its contents as an unsigned char *
 */
int server::get_file_128(char filename[], char * contents, int offset)
{
    // check if there are 16bytes left in file
    int filesize = get_filesize(filename);
    if(filesize < 0)
        return -1;
    int remaining = filesize - offset;
    int chunk_size;
    int last = 0;
    // CRYPTCHANGE //
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
    fseek(fptr, offset, SEEK_SET);
    // use size to allocate memory to
    // file buffer
    int status = fread(contents, sizeof(char), chunk_size, fptr);
    contents[LENGTH_INDEX] = chunk_size;
    contents[LAST_INDEX] = last;
    // close file
    fclose(fptr);
    return status;
}

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
    //fseek(fptr, offset, SEEK_SET);
    // use size to allocate memory to
    // file buffer
    status = fwrite(contents, sizeof(char), length, fptr);
    // close file
    fclose(fptr);
    return status;
}

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
