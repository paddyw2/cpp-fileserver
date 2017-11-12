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
    if(argc < 7) {
        cerr << "Error: not enough arguments" << endl;
        exit(EXIT_FAILURE);
    }

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
    check_cipher();

    // get key
    bzero(password, 256);
    memcpy(password, argv[6], 256);

    struct sockaddr_in dest_addr;
    int error_flag;

    // set port and IP
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    // convert hostname to ip
    char target_ip[32];
    convert_hostname_ip(target_ip, 32, hostname);
    // convert string ip to binary
    inet_aton(target_ip, &dest_addr.sin_addr);

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
    int rand_size = NONCE_SIZE;
    unsigned char *nonce = (unsigned char *)calloc(rand_size, sizeof(unsigned char));
    if (!RAND_bytes(nonce, rand_size)) {
        error("Nonce generation error");
    }

    // save to class variable
    memcpy(sent_nonce, nonce, rand_size);
    int message_len = strlen(arg_cipher) + rand_size + 1;

    // create cipher nonce message
    char cipher_nonce[message_len];
    bzero(cipher_nonce, message_len);

    // concatenate strings
    memcpy(cipher_nonce, arg_cipher, strlen(arg_cipher));
    memcpy(cipher_nonce+strlen(arg_cipher), " ", 1);
    memcpy(cipher_nonce+strlen(arg_cipher)+1, sent_nonce, rand_size);

    // send plaintext message to server
    write_to_server(cipher_nonce, message_len);
    free(nonce);
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

    // send back to server
    char crypt_digest[DIGESTSIZE+BLOCK_SIZE];
    length = encrypt_text((char *)digest, DIGESTSIZE, crypt_digest);
    write_to_server(crypt_digest, length);

    // get server status response
    char * response = (char *)malloc(RECEIVE_BUFFER);
    size = read_from_server(response, RECEIVE_BUFFER);

    // if hashes do not match, then server disconnects
    if(size == 0) {
        cerr << "Error: wrong key" << endl;
        exit(EXIT_FAILURE);
    }
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
    int status = 0;

    // calculate size to read
    int encrypt_size = ENCRYPTED_SIZE;
    if(strncmp(arg_cipher, "null", strlen("null")) == 0)
        encrypt_size = TOTAL_SIZE;

    int return_size = encrypt_size;
    int counter = 0;
    while(1) {
        // read response from server
        char * response = (char *)malloc(encrypt_size);
        return_size = read_from_server(response, encrypt_size);
        if(return_size == 0) {
            cerr << "Error: server disconnected" << endl;
            status = -1;
            break;
        } else if(return_size != ENCRYPTED_SIZE) {
            cerr << "Bad response" << endl;
            status = -1;
            break;
        }
        // decrypt response 
        char plaintext_chunk[return_size];
        int length = decrypt_text(response, return_size, plaintext_chunk);
        // check for error packet
        if(plaintext_chunk[LAST_INDEX] > 1) {
            // print error packet data
            if(plaintext_chunk[LAST_INDEX] == 2)
                cerr << "Error: file not found on server" << endl;
            status = -1;
            break;
        }
        // if normal packet, print to stdout
        fwrite(plaintext_chunk, sizeof(char), get_data_length(plaintext_chunk), stdout);
        // if packet was last packet, break loop
        if(plaintext_chunk[LAST_INDEX] == 1)
            break;
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
    int total_written = 0;
    int chunk_size = TOTAL_SIZE;
    int flag_size = FLAG_SIZE;
    int read = chunk_size - flag_size;
    while(!feof(stdin)) {
        char * file_contents = (char *) malloc(chunk_size);
        bzero(file_contents, chunk_size);
        // read chunk from stdin
        read = get_stdin_128(file_contents);
        char enc_chunk[chunk_size+BLOCK_SIZE];
        int length = encrypt_text(file_contents, chunk_size, enc_chunk);
        // send encrypted to server
        write_to_server(enc_chunk, length);
        free(file_contents);
        total_written += read;
    }
    char enc_chunk[chunk_size+BLOCK_SIZE];
    char end_msg[chunk_size];
    // set last packet flags
    end_msg[LENGTH_INDEX] = 0;
    end_msg[LAST_INDEX] = 1;
    int length = encrypt_text(end_msg, chunk_size, enc_chunk);
    write_to_server(enc_chunk, length);
    return 0;
}

int client::set_key_iv()
{
    encryption encryptor;
    // concat = (password | nonce | "IV")
    int concat_iv_len = strlen(password) + NONCE_SIZE + strlen("IV");
    char concat_iv[concat_iv_len];
    memcpy(concat_iv, password, strlen(password));
    memcpy(concat_iv+strlen(password), sent_nonce, NONCE_SIZE);
    memcpy(concat_iv+strlen(password)+NONCE_SIZE, "IV", strlen("IV"));
    iv = (unsigned char *)malloc(DIGESTSIZE);
    encryptor.get_SHA256((unsigned char *)concat_iv, concat_iv_len, iv);

    // concat_key = (password | nonce | "SK")
    int concat_key_len = strlen(password) + NONCE_SIZE + strlen("SK");
    char concat_key[concat_key_len];
    memcpy(concat_key, password, strlen(password));
    memcpy(concat_key+strlen(password), sent_nonce, NONCE_SIZE);
    memcpy(concat_key+strlen(password)+NONCE_SIZE, "SK", strlen("SK"));

    key = (unsigned char *)malloc(DIGESTSIZE);
    encryptor.get_SHA256((unsigned char *)concat_key, concat_key_len, key);

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
    //unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    //unsigned char *iv = (unsigned char *)"0123456789012345";
    ciphertext_len = encryptor.encrypt((unsigned char *)plaintext, length, key, iv, (unsigned char *)ciphertext);
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
    //unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    //unsigned char *iv = (unsigned char *)"0123456789012345";
    plaintext_len = encryptor.decrypt((unsigned char *)ciphertext, length, key, iv, (unsigned char *)plaintext);
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
int client::get_stdin_128(char file_contents[])
{
    int read = fread(file_contents, sizeof(char),DATA_SIZE,stdin);
    // set length
    int sub_count = read;
    int index = 0;
    int max_num = 125;
    while(sub_count - max_num > 0) {
        sub_count -= max_num;
        file_contents[LENGTH_INDEX+index] = 125;
        file_contents[LENGTH_INDEX+index+1] = 0;
        index++;
    }

    /* Debugging
    cerr << "----" << endl;
    cerr << TOTAL_SIZE << endl;
    cerr << read << endl;
    cerr << LENGTH_INDEX+index << endl;
    cerr << LAST_INDEX << endl;
    file_contents[LENGTH_INDEX+index] = sub_count;
    */

    // set last flag
    file_contents[LAST_INDEX] = 0;
    return read;
}

int client::check_cipher()
{
    if(strncmp(arg_cipher, "aes256", strlen("aes256")) == 0)
        return 0;
    else if(strncmp(arg_cipher, "aes128", strlen("aes128")) == 0)
        return 0;
    else if(strncmp(arg_cipher, "null", strlen("null")) == 0)
        return 0;
    else
        cerr << "Error: invalid cipher" << endl;

    exit(EXIT_FAILURE);
    return -1;
}

int client::get_data_length(char * data)
{
    int max_num = 125;
    int current = (int)data[LENGTH_INDEX];
    int total = current;
    int index = 0;
    while(current == max_num) {
        index++;
        current = (int)data[LENGTH_INDEX+index];
        total += current;
    }
    return total;
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

/*
 * Takes a hostname (such as localhost) and
 * converts it to an IP (such as 127.0.0.1
 */
int client::convert_hostname_ip(char * target_ip, int target_size, char * dest_url)
{
    // list of structs returned
    // by the getaddrinfo
    struct addrinfo * ip_info;

    // clear the target_ip string
    bzero(target_ip, target_size);

    // resolve hostname
    // NULL means no port initialized
    int error_flag = getaddrinfo(dest_url, NULL, NULL, &ip_info);

    // check for errors
    if(error_flag < 0 || ip_info == NULL)
        error("IP conversion failed\n");

    // loop through all the ip_info structs
    // and get the IP of the first one
    for(struct addrinfo * p = ip_info; p != NULL; p = p->ai_next)
    {
        // copy the socket IP address, converted to
        // readable format, to the target_ip string
        strncpy(target_ip, inet_ntoa(((struct sockaddr_in *)p->ai_addr)->sin_addr ), target_size);

        // check that a valid address was extracted
        // if so, break as we have an IP
        if(strlen(target_ip) > 0)
            break;
    }
    cerr << "Resolved to: " << target_ip << endl;
    return 0;
}
