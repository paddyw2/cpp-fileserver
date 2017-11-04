#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <string>
#include <vector>
#include <iostream>

using namespace std;

class server
{
    public:
        server(int argc, char * argv[]);
        void error(const char * msg);

    private:
        int sockfd;
        int clientsockfd;
        int portno;
        int destport;
        char * serverurl;
        struct sockaddr_in serv_addr;
        struct sockaddr_in cli_addr;
};
