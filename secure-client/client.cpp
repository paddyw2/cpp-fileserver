#include "client.h"
#include "encryption.h"

/*
 * Constructor
 * Sets up basic client connection
 */
client::client(int argc, char * argv[])
{
    if(argc < 4)
        error("Not enough arguments\n");
    // get remote connection info
    char * hostname = argv[1];
    int port = atoi(argv[2]);
    bzero(password, 256);
    memcpy(password, argv[3], 256);
    cout << "Host: " << hostname << endl;
    cout << "Port: " << port << endl;
    cout << "Password: " << password << endl;

    struct sockaddr_in dest_addr;
    int error_flag;

    // set port and IP
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    // convert string ip to binary
    inet_aton("127.0.0.1", &dest_addr.sin_addr);

    // create socket and connect to server
    serversocket = socket(AF_INET, SOCK_STREAM, 0);

    // check for errors
    if(serversocket < 0)
        error("Socket failure\n");

    error_flag = connect(serversocket, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    // check for errors
    if(error_flag < 0)
        error("Socket failure\n");
}

int client::send_cipher_nonce()
{
    char cipher_nonce[] = "AES256 blahblah";
    cout << "Sending nonce" << endl;
    write_to_server(cipher_nonce, strlen(cipher_nonce));
    return 0;
}

int client::receive_challenge()
{
    // get random challenge
    char * rand_value = (char *) calloc(128, sizeof(char));
    int size = read_from_server(rand_value, 128);
   
    // concatenate password with challenge
    char * concat = (char *) calloc(size + strlen(password), sizeof(char));
    memcpy(concat, password, strlen(password));
    memcpy(concat+strlen(password), rand_value, size);

    // calcualte hash of concatenation
    unsigned char digest[DIGESTSIZE];
    encryption encryptor;
    encryptor.get_SHA256((unsigned char *)concat, size+strlen(password), digest);
    free(concat);
    free(rand_value);
    cout << "Generated hash: ";
    for(int i=0;i<DIGESTSIZE;i++) {
        printf("%0.2x", digest[i]);
    }
    printf("\n");

    // send back to server
    write_to_server((char *)digest, DIGESTSIZE);

    // get response
    char * response = (char *)malloc(128);
    size = read_from_server(response, 128);
    decrypt_text(response, size, 0);

   return 0;
}

int client::make_request()
{
    if(1 != 1) {
        char message[] = "read test.txt";
        cout << "Sending instruction" << endl;
        write_to_server(message, strlen(message));
        char * response = (char *)malloc(128);
        int length = read_from_server(response, 128);
        length = decrypt_text(response, length, 0);
        get_server_response();
    } else {
        char message[] = "write demo.txt";
        cout << "Sending instruction" << endl;
        write_to_server(message, strlen(message));
        char * response = (char *)malloc(128);
        int length = read_from_server(response, 128);
        length = decrypt_text(response, length, 0);
        char filenme[] = "demo.txt";
        send_stdin(filenme, 0);
    }
    return 0;
}

int client::get_server_response()
{
    cout << "Receiving..." << endl;
    int return_size = 1;
    int counter = 0;
    while(return_size != 0) {
        char * response = (char *)malloc(16);
        return_size = read_from_server(response, 16);
        for(int i=0;i<return_size;i++) {
            printf("%c", response[i]);
        }
        free(response);
        counter++;
    }
    return 0;
}

int client::send_stdin(char * filename, int protocol)
{
    int chunk_size = 16;
    int read = chunk_size;
    cout << "Sending file..." << endl;
    while(read == chunk_size) {
        char * file_contents = (char *) malloc(chunk_size);
        read = get_stdin_128(filename, file_contents);
        int length = encrypt_text(file_contents, read, protocol);
        write_to_server(file_contents, length);
        free(file_contents);
        if(read < chunk_size)
            break;
    }
    cout << "Terminating..." << endl;
    return 0;
}

int client::encrypt_text(char * text, int length, int protocol)
{
    if(protocol == 0) {
        // no encryption, print for logging purposes
    }
    return length;
}

int client::decrypt_text(char * text, int length, int protocol)
{
    if(protocol == 0) {
        // no encryption, print for logging purposes
    }
    return length;
}

/*
 * Writes to client socket and checks
 * for errors
 */
int client::write_to_server(char * message, int length)
{
    int error_flag;
    error_flag = write(serversocket, message, length); 
    // error check
    if (error_flag < 0)
        error("ERROR writing to socket");

    return 0;
}

/*
 * Reads from client socket and checks
 * for errors
 */
int client::read_from_server(char * message, int length)
{
    int error_flag;
    error_flag = read(serversocket, message, length); 
    //strip_newline((char *)message, length);
    // error check
    if (error_flag < 0)
        error("ERROR reading from socket");
    return error_flag;
}

int client::get_stdin_128(char * filename, char file_contents[])
{
    FILE *fptr = stdin;
    int chunk_size = 16;
    bzero(file_contents, chunk_size);
    int length = fread(file_contents, sizeof(char), chunk_size, fptr);
    for(int i=0;i<length;i++)
        printf("%c", file_contents[i]);
    printf("\n");
    return length;
}

int client::close_socket()
{
    close(serversocket);
    return 0;
}

/*
 * Error handler
 */
void client::error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
