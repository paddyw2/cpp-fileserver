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
    //write_to_server(NULL, 0);
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
    //write_to_server(NULL, 0);

    // get response
    char * response = (char *)malloc(128);
    size = read_from_server(response, 128);
    decrypt_text(response, size, 0);

    char message[] = "--> give me that file\n";
    cout << "Sending instruction" << endl;
    write_to_server(message, strlen(message));

    get_server_response();

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
        printf("\n--> ");
        for(int i=0;i<return_size;i++) {
            printf("%c", response[i]);
        }
        free(response);
        counter++;
    }
    printf("\n");
    return 0;
}

int client::encrypt_text(char * text, int length, int protocol)
{
    if(protocol == 0) {
        // no encryption, print for logging purposes
        printf("\n--> ");
        for(int i=0;i<length;i++) {
            printf("%c", text[i]);
        }
        printf("\n");
    }
    return length;
}

int client::decrypt_text(char * text, int length, int protocol)
{
    if(protocol == 0) {
        // no encryption, print for logging purposes
        printf("\n--> ");
        for(int i=0;i<length;i++) {
            printf("%c", text[i]);
        }
        printf("\n");
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

/*
 * Checks if remote host is ready to
 * respond with data
 */
int client::check_response_ready()
{
    struct timeval timeout;
    // set timeout to be 1 second
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    fd_set active_fd_set;
    fd_set read_fd_set;
    fd_set write_fd_set;

    FD_ZERO (&active_fd_set);
    FD_SET (serversocket, &active_fd_set);

    read_fd_set = active_fd_set;
    write_fd_set = active_fd_set;
    // timeout happens when receiving an incremental
    // when the destination server is not ready to
    // return, and as we are only checking one socket
    // the select() function would block with the
    // timeout
    if(select(FD_SETSIZE, &read_fd_set, &write_fd_set, NULL, &timeout) < 0)
        error("Check select error\n");

    if(FD_ISSET(serversocket, &read_fd_set)) {
        // host is ready to respond, so
        // return 1
        return 1;
    } 
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
