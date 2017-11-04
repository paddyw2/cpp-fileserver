#include "server.h"
#include "authenticate.h"

/*
 * Constructor
 * Sets up initial server options and
 * parsing command line arguments
 */
server::server(int argc, char * argv[])
{
    // check command line arguments
    if (argc < 7) {
        fprintf(stderr,"ERROR\nUsage: ./server command filename hostname port cipher key\n");
        exit(1);
    }

    // set sever password
    bzero(password, 256);
    cout << "Set the server password: ";
    cin >> password;
    cout << "Password: " << password << endl;

    // create client socket and check for errors
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
       error("ERROR opening socket");


    char * command = argv[1];
    char * filename = argv[2];
    char * cipher = argv[5];
    char * key = argv[6];

    // convert argument to port number
    // and check for errors
    try {
        portno = stoi(argv[4]);
    } catch (const std::exception& ex) {
        error("Invalid port number\n"
              "Usage: ./proxy [logOptions] [replaceOptions] srcPort server dstPort\n");
    }

    // get destination url
    serverurl = argv[3];

    // check for restricted port number
    if(portno < 1024 || destport < 0)
       error("ERROR reserved port number");

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
        cout << "Waiting for client connection..." << endl;
        clientsockfd = accept(sockfd, (struct sockaddr *) &cli_addr,&clilen);
        // error check
        if (clientsockfd < 0)
           error("ERROR on accept");

        cout << "Got one!" << endl;
        char welcome[] = "Welcome to the server, type 'help' for "
                         "a list of commands\n";
        write_to_client(welcome, strlen(welcome), clientsockfd);
        authenticate_client();
        close(clientsockfd);
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
        error("ERROR writing to socket");
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
        error("ERROR reading from socket");
    return error_flag;
}

/*
 * Error handler
 */
void server::error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
