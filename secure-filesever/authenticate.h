#include <openssl/rand.h>
#include "encryption.h"

#define BLOCKSIZE 16
#define DIGESTSIZE 32

int server::authenticate_client()
{
    char * cipher = (char *) calloc(128, sizeof(char));
    int return_size = read_from_client(cipher, 128, clientsockfd);
    cipher[return_size-1] = 0;
    cout << "Chosen cipher: " << cipher << endl;
    free(cipher);
    char * nonce = (char *) calloc(128, sizeof(char));
    return_size = read_from_client(cipher, 128, clientsockfd);
    nonce[return_size-1] = 0;
    cout << "Chosen noncer: " << nonce << endl;
    free(nonce);

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
    char * chal_response = (char *) calloc(DIGESTSIZE, sizeof(char));
    read_from_client(chal_response, DIGESTSIZE, clientsockfd);
    
    // concatenate password with challenge
    char password[] = "secret";
    char * concat = (char *) calloc(strlen(tmp_chal) + strlen(password), sizeof(char));
    memcpy(concat, password, strlen(password));
    memcpy(concat+strlen(password), tmp_chal, strlen(tmp_chal));
    // calcualte hash of concatenation
    unsigned char digest[DIGESTSIZE];
    encryption encryptor;
    encryptor.get_SHA256((unsigned char *)concat, strlen(concat), digest);
    for(int i=0; i<DIGESTSIZE;i++)
        printf("%x", digest[i]);
    printf("\n");

    return 0;
}
