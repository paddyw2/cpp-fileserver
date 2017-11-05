/*
 * opens a file in the current directoy by name
 * and returns its contents as an unsigned char *
 */
int server::get_file_128(char filename[], char * contents, int offset)
{
    // check if there are 16bytes left in file
    int filesize = get_filesize(filename);
    int remaining = filesize - offset;
    int chunk_size;
    if(remaining > 16)
        chunk_size = 16;
    else
        chunk_size = remaining;

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
    fread(contents, sizeof(char), chunk_size, fptr);
    // close file
    fclose(fptr);
    return chunk_size;
}

int server::write_file(char filename[], char * contents, int length)
{
    // create and open file
    FILE *fptr;
    fptr = fopen(filename, "a");

    if(!fptr) {
        fptr = fopen(filename, "w");
        if(!fptr) {
            printf("File opening failed\n");
            exit(EXIT_FAILURE);
        }
    }
    //fseek(fptr, offset, SEEK_SET);
    // use size to allocate memory to
    // file buffer
    fwrite(contents, sizeof(char), length, fptr);
    // close file
    fclose(fptr);
    return length;
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
