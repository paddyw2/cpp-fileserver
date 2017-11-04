#include "client.h"

/*
 * Constructor
 * Sets up basic client connection
 */
client::client(int argc, char * argv[])
{
    if(argc < 3)
        error("Not enough arguments\n");
    // get remote connection info
    char * hostname = argv[1];
    int port = atoi(argv[2]);
    cout << "Host: " << hostname << endl;
    cout << "Port: " << port << endl;

    struct sockaddr_in dest_addr;
    int error_flag;

    // set port and IP
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    // convert string ip to binary
    inet_aton("127.0.0.1", &dest_addr.sin_addr);

    // create socket and connect to server
    clientsocket = socket(AF_INET, SOCK_STREAM, 0);

    // check for errors
    if(clientsocket < 0)
        error("Socket failure\n");

    error_flag = connect(clientsocket, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    // check for errors
    if(error_flag < 0)
        error("Socket failure\n");
}

int client::send_cipher_nonce()
{
    char cipher_nonce[] = "AES256 blahblah";
    write_to_client(cipher_nonce, strlen(cipher_nonce));
    return 0;
}

int client::receive_challenge()
{
    char * rand_value = (char *) calloc(64, sizeof(char));
    int size = read_from_client(rand_value, 64);
    cout << rand_value << endl;
    return 0;
}

/*
 * Writes to client socket and checks
 * for errors
 */
int client::write_to_client(char * message, int length)
{
    int error_flag;
    error_flag = write(clientsocket, message, length); 
    // error check
    if (error_flag < 0)
        error("ERROR writing to socket");
    return 0;
}

/*
 * Reads from client socket and checks
 * for errors
 */
int client::read_from_client(char * message, int length)
{
    int error_flag;
    error_flag = read(clientsocket, message, length); 
    //strip_newline((char *)message, length);
    // error check
    if (error_flag < 0)
        error("ERROR reading from socket");
    return error_flag;
}

/*
 * Error handler
 */
void client::error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
