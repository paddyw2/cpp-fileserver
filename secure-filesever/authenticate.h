#include <openssl/rand.h>
#include "encryption.h"

#define BLOCKSIZE 16
#define DIGESTSIZE 32

int server::authenticate_client()
{
    char * cipher_nonce = (char *) calloc(128, sizeof(char));
    int return_size = read_from_client(cipher_nonce, 128, clientsockfd);
    cout << "Chosen cipher: " << cipher_nonce << endl;
    free(cipher_nonce);

    // generate random number
    unsigned char *rand_challenge = (unsigned char *)malloc(128);
    if (!RAND_bytes(rand_challenge, 128)) {
        printf("Challenge generation error");
        exit(EXIT_FAILURE);
    }
    free(rand_challenge);

    // send random number to client as challenge
    char tmp_chal[] = "winter";
    write_to_client(tmp_chal, strlen(tmp_chal), clientsockfd);
    // read their response
    char * chal_response = (char *) calloc(DIGESTSIZE, sizeof(char));
    return_size = read_from_client(chal_response, DIGESTSIZE, clientsockfd);

    // concatenate password with challenge
    char * concat = (char *) calloc(strlen(tmp_chal) + strlen(password), sizeof(char));
    memcpy(concat, password, strlen(password));
    memcpy(concat+strlen(password), tmp_chal, strlen(tmp_chal));

    // calcualte hash of concatenation
    unsigned char digest[DIGESTSIZE];
    encryption encryptor;
    encryptor.get_SHA256((unsigned char *)concat, strlen(concat), digest);
    free(concat);

    // compare result with client response
    for(int i=0; i<DIGESTSIZE;i++) {
        if(digest[i] != (unsigned char)chal_response[i]) {
            cout << "Client authentication failed" << endl;
            exit(EXIT_FAILURE);
        }
        printf("%0.2x", digest[i]);
    }
    printf("\n");
    cout << "Client authenticated" << endl;

    // if response equals result, authenticate

    return 0;
}
