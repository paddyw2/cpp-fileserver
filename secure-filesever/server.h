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

#include "constants.h"

using namespace std;

class server
{
    public:
        server(int argc, char * argv[]);
        void error(const char * msg);
        int start_server();
        int write_to_client(char * message, int length, int client);
        int read_from_client(char * message, int length, int client);
        int authenticate_client(); 
        int get_filesize(char filename[]);
        int get_file_128(char filename[], char * contents, int offset);
        int write_file(char filename[], char * contents, int length, int total_written);
        int process_client_request();
        int send_file(char * filename, int protocol);
        int get_file(char * filename, int protocol);
        int encrypt_text(char * plaintext, int length, int protocol, char * ciphertext);
        int decrypt_text(char * ciphertext, int length, int protocol, char * plaintext);
        int get_client_file_response();
        int check_response_ready();

    private:
        char password[256];
        int sockfd;
        int clientsocket;
        int portno;
        int destport;
        char * serverurl;
        struct sockaddr_in serv_addr;
        struct sockaddr_in cli_addr;
        char cipher[32];
        char nonce[32];
        int nonce_length;
};
