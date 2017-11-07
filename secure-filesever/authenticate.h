#include <openssl/rand.h>
#include "encryption.h"

#define BLOCKSIZE 16
#define DIGESTSIZE 32

int server::authenticate_client()
{
    char * cipher_nonce = (char *) calloc(128, sizeof(char));
    int return_size = read_from_client(cipher_nonce, 128, clientsocket);
    cout << "Chosen cipher: " << cipher_nonce << endl;
    free(cipher_nonce);

    // generate random number
    int rand_size = 64;
    unsigned char *rand_challenge = (unsigned char *)calloc(rand_size, sizeof(unsigned char));
    if (!RAND_bytes(rand_challenge, rand_size)) {
        printf("Challenge generation error");
        exit(EXIT_FAILURE);
    }

    // send random number to client as challenge
    //char tmp_chal[] = "winter!";
    //rand_challenge = (unsigned char *)tmp_chal;
    //rand_size = strlen(tmp_chal);
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
    cout << "Generated hash: ";
    int fail = 0;
    for(int i=0; i<DIGESTSIZE;i++) {
        if(digest[i] != (unsigned char)chal_response[i])
            fail = 1;
        printf("%0.2x", digest[i]);
    }
    printf("\n");
    if(fail == 1) {
        cout << "Client authentication failed" << endl;
        exit(EXIT_FAILURE);
    } else {
        cout << "Client authenticated" << endl;
        char success[] = "You are authed\n";
        cout << "Sending success..." << endl;
        send_message_client(success, strlen(success), 0);

    }

    // if response equals result, authenticate

    return 0;
}
