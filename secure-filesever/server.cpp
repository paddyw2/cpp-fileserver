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
            int status = process_client_request();
            if(status < 0)
                cerr << "Communication error" << endl;
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
    char * ciphertext = (char *)malloc(length+434);
    int cipher_length = encrypt_text(message, length, 0, ciphertext);
    error_flag = write(client, ciphertext, cipher_length);
    free(ciphertext);
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
    char * plaintext = (char *)malloc(length);
    int plaintext_length = decrypt_text(message, length, 0, plaintext);
    // print out reponse?
    free(plaintext);
    return error_flag;
}

/*
 * Checks if remote host is ready to
 * respond with data
 */
int server::check_response_ready()
{
    struct timeval timeout;
    // set timeout to be 1 second
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    fd_set active_fd_set;
    fd_set read_fd_set;
    fd_set write_fd_set;

    FD_ZERO (&active_fd_set);
    FD_SET (clientsocket, &active_fd_set);

    read_fd_set = active_fd_set;
    write_fd_set = active_fd_set;
    // timeout happens when receiving an incremental
    // when the destination server is not ready to
    // return, and as we are only checking one socket
    // the select() function would block with the
    // timeout
    if(select(FD_SETSIZE, &read_fd_set, &write_fd_set, NULL, &timeout) < 0)
        error("Check select error\n");

    if(FD_ISSET(clientsocket, &read_fd_set)) {
        // host is ready to respond, so
        // return 1
        return 1;
    } 
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
