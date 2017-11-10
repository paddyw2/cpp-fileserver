#include <openssl/rand.h>
#include "encryption.h"
#include "client.h"
#include "request.h"

/*
 * Constructor
 * Sets up basic client connection
 */
client::client(int argc, char * argv[])
{
    if(argc < 7)
        error("Not enough arguments\n");

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

/*
 * Send the specified cipher to
 * the server, along with a randomly
 * generated nonce in plaintext
 */
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

/*
 * Receive a random challenge from
 * the server and compute:
 * sha256(password | challenge)
 * and send the result back to
 * the server to complete
 * authentication
 */
int client::receive_challenge()
{
    // get random challenge
    char * rand_value = (char *) calloc(128, sizeof(char));
    int size = read_from_server(rand_value, 128);
    char rand_plaintext[size];
    int length = decrypt_text(rand_value, size, rand_plaintext);
   
    // concatenate password with challenge
    char * concat = (char *) calloc(length + strlen(password), sizeof(char));
    memcpy(concat, password, strlen(password));
    memcpy(concat+strlen(password), rand_plaintext, length);

    // calcualte hash of concatenation
    unsigned char digest[DIGESTSIZE];
    encryption encryptor;
    encryptor.get_SHA256((unsigned char *)concat, length+strlen(password), digest);
    free(concat);
    free(rand_value);

    // print generated hash
    cerr << "Generated hash: ";
    for(int i=0;i<DIGESTSIZE;i++) {
        fprintf(stderr, "%0.2x", digest[i]);
    }
    fprintf(stderr, "\n");

    // send back to server
    char crypt_digest[DIGESTSIZE+BLOCK_SIZE];
    length = encrypt_text((char *)digest, DIGESTSIZE, crypt_digest);
    write_to_server(crypt_digest, length);

    // get server status response
    char * response = (char *)malloc(128);
    size = read_from_server(response, 128);
    // if failed, then server disconnects
    if(size <= 0)
        error("Authentication failed\n");
    char plaintext[size];
    decrypt_text(response, size, plaintext);
    free(response);

   return 0;
}

/*
 * Receive a file in chunks from
 * the server and print to stdout
 */
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
        int length = decrypt_text(response, return_size, plaintext_chunk);
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

/*
 * Read data chunks from stdin, encrypt,
 * and send to server until EOF is
 * detected
 */
int client::send_stdin(char * filename)
{
    int chunk_size = TOTAL_SIZE;
    int flag_size = FLAG_SIZE;
    int read = chunk_size - flag_size;
    cerr << "Sending file..." << endl;
    while(read == chunk_size - flag_size) {
        char * file_contents = (char *) malloc(chunk_size);
        bzero(file_contents, chunk_size);
        read = get_stdin_128(filename, file_contents);
        char enc_chunk[chunk_size+BLOCK_SIZE];
        cerr << "SIZE 1: " << read+434 << endl;
        cerr << "CHUNK: " << chunk_size << endl;
        cerr << "READ: " << read << endl;
        int length = encrypt_text(file_contents, chunk_size, enc_chunk);
        write_to_server(enc_chunk, length);
        free(file_contents);
    }
    return 0;
}

/*
 * Encrypt plaintext using chosen cipher
 */
int client::encrypt_text(char * plaintext, int length, char * ciphertext)
{
    int ciphertext_len;
    // aes256
    encryption encryptor(arg_cipher);
    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    ciphertext_len = encryptor.encrypt((unsigned char *)plaintext, length, key, iv, (unsigned char *)ciphertext);
    cerr << "Cipher length: " << ciphertext_len << endl;
    return ciphertext_len;
}

/*
 * Decrypt ciphertext using chosen cipher
 */
int client::decrypt_text(char * ciphertext, int length, char * plaintext)
{
    int plaintext_len;
    // aes256
    encryption encryptor(arg_cipher);
    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    plaintext_len = encryptor.decrypt((unsigned char *)ciphertext, length, key, iv, (unsigned char *)plaintext);
    cerr << "Decrypt length: " << plaintext_len << endl;
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

/*
 * Reads data chunks from stdin
 * into file_contents
 * Returns size of data chunk
 * read
 */
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

/*
 * Closes the client socket cleanly
 */
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
