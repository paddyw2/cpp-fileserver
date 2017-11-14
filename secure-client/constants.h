/*
 * Description:
 * Receive buffer and encrypted size should be the same
 * Total size must be less than the encrypted size, but BLOCK_SIZE less is safer
 * Flag size: 1 (for last/error flag) + # required for representing the max possible
 * data length (i.e. DATA_SIZE)
 * To calculate this: TOTAL_SIZE / 125 = # required length data
 * Data size is total size - flag size
 * Last index is where the last/error flags are stored
 * Length idnex is the start of the length section (in this case is 66bytes long)
 */
#define NONCE_SIZE 16
#define DIGESTSIZE 32
#define BLOCK_SIZE 16
#define RECEIVE_BUFFER 512
#define ENCRYPTED_SIZE 512
#define TOTAL_SIZE 496
#define FLAG_SIZE 5
#define DATA_SIZE 491
#define LAST_INDEX 495
#define LENGTH_INDEX 491
