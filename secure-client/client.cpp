#include <openssl/rand.h>
#include "client.h"
#include "encryption.h"

/*
 * Constructor
 * Sets up basic client connection
 */
client::client(int argc, char * argv[])
{
    if(argc < 7)
        error("Not enough arguments\n");
    // get remote connection info
    // ./client read test.txt localhost 8080 aes256 secret
    // get command
    bzero(arg_command, 32);
    memcpy(arg_command, argv[1], 32);
    // get filename
    bzero(arg_filename, 128);
    memcpy(arg_filename, argv[2], 128);
    // get network info
    char * hostname = argv[3];
    int port = atoi(argv[4]);
    // get cipher
    bzero(arg_cipher, 32);
    memcpy(arg_cipher, argv[5], 32);
    // get key
    bzero(password, 256);
    memcpy(password, argv[6], 256);
    // print info
    cerr << "Host: " << hostname << endl;
    cerr << "Port: " << port << endl;
    cerr << "Password: " << password << endl;

    struct sockaddr_in dest_addr;
    int error_flag;

    // set port and IP
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    // convert string ip to binary
    inet_aton("127.0.0.1", &dest_addr.sin_addr);

    // create socket and connect to server
    serversocket = socket(AF_INET, SOCK_STREAM, 0);

    // check for errors
    if(serversocket < 0)
        error("Socket failure\n");

    error_flag = connect(serversocket, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    // check for errors
    if(error_flag < 0)
        error("Socket failure\n");
}

int client::send_cipher_nonce()
{
    // generate random number
    int rand_size = 16;
    unsigned char *nonce = (unsigned char *)calloc(rand_size, sizeof(unsigned char));
    if (!RAND_bytes(nonce, rand_size)) {
        fprintf(stderr, "Nonce generation error");
        exit(EXIT_FAILURE);
    }
    int message_len = strlen(arg_cipher) + rand_size + 1;
    // create cipher nonce message
    char cipher_nonce[message_len];
    bzero(cipher_nonce, message_len);
    // concatenate strings
    memcpy(cipher_nonce, arg_cipher, strlen(arg_cipher));
    memcpy(cipher_nonce+strlen(arg_cipher), " ", 1);
    memcpy(cipher_nonce+strlen(arg_cipher)+1, nonce, rand_size);
    cerr << "Sending nonce" << endl;
    write_to_server(cipher_nonce, strlen(cipher_nonce));
    return 0;
}

int client::receive_challenge()
{
    // get random challenge
    char * rand_value = (char *) calloc(128, sizeof(char));
    int size = read_from_server(rand_value, 128);
   
    // concatenate password with challenge
    char * concat = (char *) calloc(size + strlen(password), sizeof(char));
    memcpy(concat, password, strlen(password));
    memcpy(concat+strlen(password), rand_value, size);

    // calcualte hash of concatenation
    unsigned char digest[DIGESTSIZE];
    encryption encryptor;
    encryptor.get_SHA256((unsigned char *)concat, size+strlen(password), digest);
    free(concat);
    free(rand_value);
    cerr << "Generated hash: ";
    for(int i=0;i<DIGESTSIZE;i++) {
        fprintf(stderr, "%0.2x", digest[i]);
    }
    fprintf(stderr, "\n");

    // send back to server
    write_to_server((char *)digest, DIGESTSIZE);

    // get response
    char * response = (char *)malloc(128);
    size = read_from_server(response, 128);
    decrypt_text(&response, size, 0);

   return 0;
}

int client::make_request()
{
    // contains main program logic
    // checks for read or write command
    // then send appropriate protocol messages
    if(strncmp(arg_command, "read", strlen("read")) == 0) {
        cerr << "Read chosen" << endl;
        // formulate request of format: read [filename]
        int message_len = strlen("read ")+strlen(arg_filename)+1;
        char * message = (char *) malloc(message_len);
        bzero(message, message_len);
        // concatenate strings
        memcpy(message, "read ", strlen("read "));
        memcpy(message+strlen("read "), arg_filename, strlen(arg_filename));
        // encrypt message and send to server
        cerr << "Request: " << message << endl;
        int length = encrypt_text(&message, strlen(message), 0);
        write_to_server(message, length);
        free(message);
        // get acknowledgment back from server
        char * response = (char *)malloc(128);
        length = read_from_server(response, 128);
        length = decrypt_text(&response, length, 0);
        free(response);
        // now output server response to stdout
        int status = get_server_response();
        // now send success message back
        if(status < 0) {
            char * success = (char *)malloc(TOTAL_SIZE);
            memcpy(success, "FAIL", strlen("FAIL"));
            length = encrypt_text(&success, strlen(success), 0);
            write_to_server(success, length);
            free(success);
            cerr << "FAIL" << endl;
        } else {
            char * success = (char *)malloc(TOTAL_SIZE);
            memcpy(success, "OK", strlen("OK"));
            length = encrypt_text(&success, strlen(success), 0);
            write_to_server(success, length);
            free(success);
            cerr << "Sent OK" << endl;
        }
    } else {
        cerr << "Write chosen" << endl;
        // formulate request of format: write [filename]
        int message_len = strlen("write ")+strlen(arg_filename)+1;
        char * message = (char *)malloc(message_len);
        bzero(message, message_len);
        // concatenate strings
        memcpy(message, "write ", strlen("write "));
        memcpy(message+strlen("write "), arg_filename, strlen(arg_filename));
        // encrypt message and send to sever
        int length = encrypt_text(&message, strlen(message), 0);
        write_to_server(message, strlen(message));
        free(message);
        // get acknowledgment back from server
        char * response = (char *)malloc(128);
        length = read_from_server(response, 128);
        length = decrypt_text(&response, length, 0);
        // now send stdin to server
        send_stdin(arg_filename, 0);
        // now get server success message back
        bzero(response, 128);
        length = read_from_server(response, 128);
        length = decrypt_text(&response, length, 0);
        cerr << "Server status: " << response << endl;
        free(response);
    }
    return 0;
}

int client::get_server_response()
{
    cerr << "Receiving..." << endl;
    int status = 0;
    int return_size = TOTAL_SIZE;
    int counter = 0;
    while(1) {
        cerr << "Getting" << endl;
        char * response = (char *)malloc(TOTAL_SIZE);
        return_size = read_from_server(response, TOTAL_SIZE);
        int length = decrypt_text(&response, return_size, 0);
        if(return_size <= 0) {
            cerr << "Status: FAIL" << endl;
            status = -1;
            break;
        }
        if(response[LAST_INDEX] == 1) {
            cerr << "Detected last packet" << endl;
            for(int i=0;i<(int)response[LENGTH_INDEX];i++) {
                printf("%c", response[i]);
            }
            cerr << "Status: OK" << endl;
            break;
        } else if(response[LAST_INDEX] == 2) {
            // error packet
            cerr << "Server status: ";
            for(int i=0;i<(int)response[LENGTH_INDEX];i++) {
                fprintf(stderr,"%c", response[i]);
            }
            fprintf(stderr,"\n");
            status = -1;
            break;
        }
        for(int i=0;i<(int)response[LENGTH_INDEX];i++) {
            printf("%c", response[i]);
        }
        free(response);
        counter++;
    }
    return status;
}

int client::send_stdin(char * filename, int protocol)
{
    int chunk_size = TOTAL_SIZE;
    int flag_size = FLAG_SIZE;
    int read = DATA_SIZE;
    cerr << "Sending file..." << endl;
    while(read == DATA_SIZE) {
        char * file_contents = (char *) malloc(chunk_size);
        bzero(file_contents, chunk_size);
        read = get_stdin_128(filename, file_contents);
        int length = encrypt_text(&file_contents, chunk_size, protocol);
        write_to_server(file_contents, length);
        free(file_contents);
    }
    return 0;
}

int client::encrypt_text(char ** text, int length, int protocol)
{
    int ciphertext_len;
    int block_size = 16;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        // make cipher text big enough to account for padding
        unsigned char * ciphertext = (unsigned char *)malloc(length+block_size*2);
        ciphertext_len = encryptor.encrypt((unsigned char *)*text, length, key, iv, ciphertext);
        cerr << "Cipher length: " << ciphertext_len << endl;
        // resize input and copy result to memory location
        *text = (char *)realloc(*text, ciphertext_len);
        memcpy(*text, ciphertext, ciphertext_len);
        free(ciphertext);
    }
    return ciphertext_len;
}

int client::decrypt_text(char ** text, int length, int protocol)
{
    int decrypt_len;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";

        // plaintext will be equal or less than cipher length
        unsigned char * plaintext = (unsigned char *)malloc(length);
        bzero(plaintext, length);
        decrypt_len = encryptor.decrypt((unsigned char *)*text, length, key, iv, plaintext);
        cerr << "Decrypt length: " << decrypt_len << endl;
        for(int i=0;i<decrypt_len;i++)
            cerr << plaintext[i];
        cerr << endl;
        // resize input and copy result to memory location
        *text = (char *)realloc(*text, decrypt_len);
        memcpy(*text, plaintext, decrypt_len);
        free(plaintext);
    }

    return decrypt_len;
}

/*
 * Writes to client socket and checks
 * for errors
 */
int client::write_to_server(char * message, int length)
{
    int error_flag;
    error_flag = write(serversocket, message, length); 
    // error check
    if (error_flag < 0)
        error("ERROR writing to socket");

    return 0;
}

/*
 * Reads from client socket and checks
 * for errors
 */
int client::read_from_server(char * message, int length)
{
    int error_flag;
    error_flag = read(serversocket, message, length); 
    //strip_newline((char *)message, length);
    // error check
    if (error_flag <= 0)
        error("ERROR reading from socket");

    cerr << error_flag << endl;
    return error_flag;
}

int client::get_stdin_128(char * filename, char file_contents[])
{
    int index = 0;
    int last = 0;
    while(index < DATA_SIZE) {
        char val = getchar();
        if(val == EOF) {
            last = 1;
            break;
        }
        file_contents[index] = val;
        index++;
    }
    // set length
    file_contents[LENGTH_INDEX] = index;
    // set last flag
    file_contents[LAST_INDEX] = last;
    return index;
}

int client::close_socket()
{
    close(serversocket);
    return 0;
}

/*
 * Error handler
 */
void client::error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}
