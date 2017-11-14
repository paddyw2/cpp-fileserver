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
#define RECEIVE_BUFFER 1024 
#define ENCRYPTED_SIZE 1024 
#define TOTAL_SIZE 1008 
#define FLAG_SIZE 10 
#define DATA_SIZE 998 
#define LAST_INDEX 1007 
#define LENGTH_INDEX 998
#define aRECEIVE_BUFFER 8192
#define aENCRYPTED_SIZE 8192
#define aTOTAL_SIZE 8176
#define aFLAG_SIZE 67
#define aDATA_SIZE 8109
#define aLAST_INDEX 8175
#define aLENGTH_INDEX 8109
