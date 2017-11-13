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

#include "constants.h"

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
        int set_key_iv();
        int encrypt_text(char * plaintext, int length, char * ciphertext);
        int decrypt_text(char * ciphertext, int length, char * plaintext);
        int get_stdin_128(char file_contents[]);
        int send_stdin(char * filename);
        int check_cipher();
        int close_socket();
        int get_data_length(char * data);
        int convert_hostname_ip(char * target_ip, int target_size, char * dest_url);

    private:
        int serversocket;
        char password[256];
        char arg_command[32];
        char arg_cipher[32];
        char arg_filename[128];
        char sent_nonce[NONCE_SIZE+1];
        unsigned char * key;
        unsigned char * iv;
};
