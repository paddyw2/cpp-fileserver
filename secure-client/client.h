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

#define DIGESTSIZE 32

using namespace std;

class client
{
    public:
        client(int argc, char * argv[]);
        void error(const char * msg);
        int send_cipher_nonce();
        int receive_challenge();
        int read_from_server(char * message, int length);
        int write_to_server(char * message, int length);
        int get_server_response();
        int check_response_ready();
        int make_request();
        int encrypt_text(char * text, int length, int protocol);
        int decrypt_text(char * text, int length, int protocol);
        int get_stdin_128(char * filename, char file_contents[]);
        int send_stdin(char * filename, int protocol);
        int close_socket();

    private:
        int serversocket;
        char password[256];

};
