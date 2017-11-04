#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <iostream>

using namespace std;

class client
{
    public:
        client(int argc, char * argv[]);
        void error(const char * msg);
        int send_cipher_nonce();
        int receive_challenge();
        int read_from_client(char * message, int length);
        int write_to_client(char * message, int length);
    private:
        int clientsocket;

};
