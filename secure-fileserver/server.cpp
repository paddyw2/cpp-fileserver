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

    cerr << "Listening on port " << portno << endl;
    cerr << "Using secret key: " << password << endl;
}

/*
 * Starts the main server loop that
 * infinitely waits for and handles
 * client connections
 */
int server::start_server()
{
    socklen_t clilen = sizeof(cli_addr);
    while(1) {
        clientsocket = accept(sockfd, (struct sockaddr *) &cli_addr,&clilen);
        // error check
        if(clientsocket < 0) {
           cerr << "ERROR on accept" << endl;
           continue;
        }

        print_time();
        printf("New connection from: %s", inet_ntoa(cli_addr.sin_addr));
        printf(" cipher=");
        int status = authenticate_client();
        if(status != -1) {
            process_client_request();
        }
        free(iv);
        free(key);
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
    return error_flag;
}

/*
 * Reads from client socket and checks
 * for errors
 */
int server::read_from_client(char * message, int length, int client)
{
    int error_flag;
    error_flag = read(client, message, length);
    // error check
    if (error_flag < 0)
        error("ERROR reading from socket\n");
    return error_flag;
}

/*
 * Generates IV and SK based on password
 * and shared random nonce
 */
int server::set_key_iv()
{
    encryption encryptor;
    // concat = (password | nonce | "IV")
    int concat_iv_len = strlen(password) + NONCE_SIZE + strlen("IV");
    char concat_iv[concat_iv_len];
    memcpy(concat_iv, password, strlen(password));
    memcpy(concat_iv+strlen(password), nonce, NONCE_SIZE);
    memcpy(concat_iv+strlen(password)+NONCE_SIZE, "IV", strlen("IV"));
    iv = (unsigned char *)malloc(DIGESTSIZE);
    encryptor.get_SHA256((unsigned char *)concat_iv, concat_iv_len, iv);

    // concat_key = (password | nonce | "SK")
    int concat_key_len = strlen(password) + NONCE_SIZE + strlen("SK");
    char concat_key[concat_key_len];
    memcpy(concat_key, password, strlen(password));
    memcpy(concat_key+strlen(password), nonce, NONCE_SIZE);
    memcpy(concat_key+strlen(password)+NONCE_SIZE, "SK", strlen("SK"));
    
    key = (unsigned char *)malloc(DIGESTSIZE);
    encryptor.get_SHA256((unsigned char *)concat_key, concat_key_len, key);

    // print IV
    print_time();
    printf("IV=");
    for(int i=0;i<DIGESTSIZE;i++)
        printf("%0.2x", iv[i]);
    printf("\n");
    // print SK
    print_time();
    printf("SK=");
    for(int i=0;i<DIGESTSIZE;i++)
        printf("%0.2x", key[i]);
    printf("\n");

    return 0;
}

/*
 * Encrypts the plaintext parameter into the ciphertext
 * buffer, and returns the length of the encrypted data
 */
int server::encrypt_text(char * plaintext, int length, char * ciphertext)
{
    int ciphertext_len;
    // aes256
    encryption encryptor(cipher);
    /* A 256 bit key */
    //unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    //unsigned char *iv = (unsigned char *)"0123456789012345";
    ciphertext_len = encryptor.encrypt((unsigned char *)plaintext, length, key, iv, (unsigned char *)ciphertext);
    return ciphertext_len;
}

/*
 * Decrypts the ciphertext parameter into the plaintext
 * buffer, and returns the length of the decrypted data
 */
int server::decrypt_text(char * ciphertext, int length, char * plaintext)
{
    int plaintext_len;
    // aes256
    encryption encryptor(cipher);
    /* A 256 bit key */
    //unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    //unsigned char *iv = (unsigned char *)"0123456789012345";
    plaintext_len = encryptor.decrypt((unsigned char *)ciphertext, length, key, iv, (unsigned char *)plaintext);
    return plaintext_len;
}

/*
 * Prints the current time in a formatted
 * way that allows it to be used for
 * logging purposes
 */
int server::print_time()
{
    time_t timer;
    char buffer[26];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%H:%M:%S", tm_info);
    printf("%s ", buffer);

    return 0;
}

/*
 * Error handler
 */
void server::error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
