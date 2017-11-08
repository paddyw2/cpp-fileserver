#include <openssl/rand.h>
#include "encryption.h"

#define BLOCKSIZE 16
#define DIGESTSIZE 32

int server::authenticate_client()
{
    char * cipher_nonce = (char *) calloc(128, sizeof(char));
    int return_size = read_from_client(cipher_nonce, 127, clientsocket);
    // parse and extract nonce and cipher information from
    // message
    int index = 0;
    while(cipher_nonce[index] != ' ') {
        cipher[index] = cipher_nonce[index];
        index++;
        if(index >= 31) {
            cerr << "Bad cipher" << endl;
            return -1;
        }
    }
    cipher[index] = 0;
    cerr << "Cipher: " << cipher << endl;
    cerr << "Nonce: ";
    index++;
    int new_index = 0;
    while(index < return_size) {
        nonce[new_index] = cipher_nonce[index];
        fprintf(stderr, "%c", nonce[new_index]);
        index++;
        new_index++;
        if(new_index >= 31) {
            cerr << "Bad nonce" << endl;
            return -1;
        }
    }
    fprintf(stderr, "\n");
    nonce_length = new_index;
    free(cipher_nonce);
    // information extraction finished

    // generate random number
    int rand_size = 64;
    unsigned char *rand_challenge = (unsigned char *)calloc(rand_size, sizeof(unsigned char));
    if (!RAND_bytes(rand_challenge, rand_size)) {
        printf("Challenge generation error");
        exit(EXIT_FAILURE);
    }

    // send random number to client as challenge
    write_to_client((char *)rand_challenge, rand_size, clientsocket);
    // read their response
    char * chal_response = (char *) calloc(DIGESTSIZE, sizeof(char));
    return_size = read_from_client(chal_response, DIGESTSIZE, clientsocket);

    // concatenate password with challenge
    char * concat = (char *) calloc(rand_size + strlen(password), sizeof(char));
    memcpy(concat, password, strlen(password));
    memcpy(concat+strlen(password), rand_challenge, rand_size);

    // calcualte hash of concatenation
    unsigned char digest[DIGESTSIZE];
    encryption encryptor;
    encryptor.get_SHA256((unsigned char *)concat, rand_size + strlen(password), digest);
    free(concat);

    // compare result with client response
    cerr << "Generated hash: ";
    int fail = 0;
    for(int i=0; i<DIGESTSIZE;i++) {
        if(digest[i] != (unsigned char)chal_response[i])
            fail = 1;
        printf("%0.2x", digest[i]);
    }
    printf("\n");
    if(fail == 1) {
        cerr << "Client authentication failed" << endl;
        return -1;
    } else {
        cerr << "Client authenticated" << endl;
        char * success = (char *)malloc(TOTAL_SIZE);
        memcpy(success,"You are authed", strlen("You are authed"));
        cerr << "Sending success..." << endl;
        char * ciphertext = (char *)malloc(strlen("You are authed")+434);
        int length = encrypt_text(success, strlen(success), 0, ciphertext);
        write_to_client(ciphertext, length, clientsocket);
        free(success);
        free(ciphertext);
    }

    return 0;
}
