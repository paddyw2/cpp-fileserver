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
    char plaintext[size];
    decrypt_text(response, size, 0, plaintext);
    free(response);

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
        char message[message_len];
        bzero(message, message_len);
        // concatenate strings
        memcpy(message, "read ", strlen("read "));
        memcpy(message+strlen("read "), arg_filename, strlen(arg_filename));
        // encrypt message and send to server
        char enc_msg[message_len+434];
        int length = encrypt_text(message, strlen(message), 0, enc_msg);
        write_to_server(enc_msg, length);
        // get acknowledgment back from server
        char * response = (char *)malloc(128);
        length = read_from_server(response, 128);
        char plaintext[length];
        length = decrypt_text(response, length, 0, plaintext);
        // now output server response to stdout
        int status = get_server_response();
        // now send success message back
        if(status < 0) {
            char success[] = "FAIL";
            char enc_success[strlen("FAIL")+434];
            length = encrypt_text(success, strlen(success), 0, enc_success);
            write_to_server(enc_success, length);
            cerr << "FAIL" << endl;
        } else {
            char success[] = "OK";
            char enc_success[strlen("OK")+434];
            length = encrypt_text(success, strlen(success), 0, enc_success);
            write_to_server(enc_success, length);
            cerr << "Sent OK" << endl;
        }
    } else {
        cerr << "Write chosen" << endl;
        // formulate request of format: write [filename]
        int message_len = strlen("write ")+strlen(arg_filename)+1;
        char message[message_len];
        bzero(message, message_len);
        // concatenate strings
        memcpy(message, "write ", strlen("write "));
        memcpy(message+strlen("write "), arg_filename, strlen(arg_filename));
        // encrypt message and send to sever
        char enc_msg[message_len+434];
        int length = encrypt_text(message, strlen(message), 0, enc_msg);
        write_to_server(enc_msg, length);
        // get acknowledgment back from server
        char * response = (char *)malloc(128);
        length = read_from_server(response, 128);
        char plaintext[length];
        length = decrypt_text(response, length, 0, plaintext);
        // now send stdin to server
        send_stdin(arg_filename, 0);
        // now get server success message back
        bzero(response, 128);
        length = read_from_server(response, 128);
        char plain_res[length];
        length = decrypt_text(response, length, 0, plain_res);
        cerr << "Server status: " << plain_res << endl;
    }
    return 0;
}

int client::get_server_response()
{
    cerr << "Receiving..." << endl;
    int status = 0;
    int return_size = ENCRYPTED_SIZE;
    int counter = 0;
    while(1) {
        char * response = (char *)malloc(ENCRYPTED_SIZE);
        return_size = read_from_server(response, ENCRYPTED_SIZE);
        char plaintext_chunk[return_size];
        int length = decrypt_text(response, return_size, 0, plaintext_chunk);
        if(return_size <= 0) {
            cerr << "Status: FAIL" << endl;
            status = -1;
            break;
        }
        if(plaintext_chunk[LAST_INDEX] == 1) {
            cerr << "Detected last packet" << endl;
            for(int i=0;i<(int)plaintext_chunk[LENGTH_INDEX];i++) {
                printf("%c", plaintext_chunk[i]);
            }
            cerr << "Status: OK" << endl;
            break;
        } else if(plaintext_chunk[LAST_INDEX] == 2) {
            // error packet
            cerr << "Server status: ";
            for(int i=0;i<(int)plaintext_chunk[LENGTH_INDEX];i++) {
                fprintf(stderr,"%c", plaintext_chunk[i]);
            }
            fprintf(stderr,"\n");
            status = -1;
            break;
        }
        for(int i=0;i<(int)plaintext_chunk[LENGTH_INDEX];i++) {
            printf("%c", plaintext_chunk[i]);
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
    int read = chunk_size - flag_size;
    cerr << "Sending file..." << endl;
    while(read == chunk_size - flag_size) {
        char * file_contents = (char *) malloc(chunk_size);
        bzero(file_contents, chunk_size);
        read = get_stdin_128(filename, file_contents);
        char enc_chunk[read+434];
        int length = encrypt_text(file_contents, chunk_size, protocol, enc_chunk);
        write_to_server(enc_chunk, length);
        free(file_contents);
    }
    return 0;
}

int client::encrypt_text(char * plaintext, int length, int protocol, char * ciphertext)
{
    int ciphertext_len;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        ciphertext_len = encryptor.encrypt((unsigned char *)plaintext, length, key, iv, (unsigned char *)ciphertext);
        cerr << "Cipher length: " << ciphertext_len << endl;
    }
    return ciphertext_len;
}

int client::decrypt_text(char * ciphertext, int length, int protocol, char * plaintext)
{
    int plaintext_len;
    if(protocol != 0) {
        // no encryption, print for logging purposes
    } else {
        // aes256
        encryption encryptor;
        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";
        plaintext_len = encryptor.decrypt((unsigned char *)ciphertext, length, key, iv, (unsigned char *)plaintext);
        cerr << "Decrypt length: " << plaintext_len << endl;
    }
    return plaintext_len;
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
    if (error_flag < 0)
        error("ERROR reading from socket");
    return error_flag;
}

int client::get_stdin_128(char * filename, char file_contents[])
{
    int index = 0;
    int last = 0;
    while(index < 14) {
        char val = getchar();
        if(val == EOF) {
            last = 1;
            break;
        }
        file_contents[index] = val;
        index++;
    }
    // set length
    file_contents[14] = index;
    // set last flag
    file_contents[15] = last;
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
