#include "server.h"
#include "authenticate.h"
#include "file.h"
#include "processor.h"

/*
 * Constructor
 * Sets up initial server options and
 * parsing command line arguments
 */
server::server(int argc, char * argv[])
{
    // check command line arguments
    if (argc < 3) {
        fprintf(stderr,"ERROR\nUsage: ./server port key\n");
        exit(1);
    }

    // set sever password
    bzero(password, 256);
    memcpy(password, argv[2], 256);

    // create client socket and check for errors
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
       error("ERROR opening socket\n");

    // convert argument to port number
    // and check for errors
    try {
        portno = stoi(argv[1]);
    } catch (const std::exception& ex) {
        error("Invalid port number\n"
              "Usage: ./proxy [logOptions] [replaceOptions] srcPort server dstPort\n");
    }

    // check for restricted port number
    if(portno < 1024 || destport < 0)
       error("ERROR reserved port number\n");

    // clear structures and set to chosen values
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    // bind socket to chosen address and port
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
             sizeof(serv_addr)) < 0)
             error("ERROR on binding");

    // start listening for connections on the
    // created socket
    listen(sockfd,5);
}

int server::start_server()
{
    socklen_t clilen = sizeof(cli_addr);
    while(1) {
        cerr << "Waiting for client connection..." << endl;
        clientsocket = accept(sockfd, (struct sockaddr *) &cli_addr,&clilen);
        // error check
        if(clientsocket < 0) {
           cerr << "ERROR on accept" << endl;
           continue;
        }

        cerr << "Connected with client" << endl;
        int status = authenticate_client();
        if(status != -1) {
            process_client_request();
        }
        close(clientsocket);
    }
    return 0;
}


/*
 * Writes to client socket and checks
 * for errors
 */
int server::write_to_client(char * message, int length, int client)
{
    int error_flag;
    error_flag = write(client, message, length);
    // error check
    if (error_flag < 0)
        error("ERROR writing to socket\n");
    return 0;
}

/*
 * Reads from client socket and checks
 * for errors
 */
int server::read_from_client(char * message, int length, int client)
{
    int error_flag;
    error_flag = read(client, message, length);
    //strip_newline((char *)message, length);
    // error check
    if (error_flag < 0)
        error("ERROR reading from socket\n");
    return error_flag;
}

int server::encrypt_text(char * plaintext, int length, int protocol, char * ciphertext)
{
    int ciphertext_len;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        ciphertext_len = encryptor.encrypt((unsigned char *)plaintext, length, key, iv, (unsigned char *)ciphertext);
        cerr << "Cipher length: " << ciphertext_len << endl;
    }
    return ciphertext_len;
}

int server::decrypt_text(char * ciphertext, int length, int protocol, char * plaintext)
{
    int plaintext_len;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        plaintext_len = encryptor.decrypt((unsigned char *)ciphertext, length, key, iv, (unsigned char *)plaintext);
        cerr << "Decrypt length: " << plaintext_len << endl;
    }
    return plaintext_len;
}


/*
 * Error handler
 */
void server::error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
