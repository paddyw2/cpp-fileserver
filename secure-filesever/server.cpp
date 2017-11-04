#include "server.h"

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

/*
 * Error handler
 */
void server::error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
