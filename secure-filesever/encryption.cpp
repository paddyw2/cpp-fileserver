#include "encryption.h"

/* OPENSSL code
 * Link: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 * Customized slightly to work with file encryption
 */

/*
 * General error handler
 * Gives verbose error
 */
void encryption::handle_errors(void)
{
  fprintf(stderr, "Error detected!\n");
  ERR_print_errors_fp(stderr);
  abort();
}

/*
 * Custom encryption error message
 */
void encryption::encryption_error(void)
{
    fprintf(stderr, "Encryption failed\n");
    exit(EXIT_FAILURE);
}

/*
 * Custom error message for incorrect password
 */
void encryption::decryption_error(void)
{
    fprintf(stderr, "Decryption failed\n");
    fprintf(stderr, "Please double check your password and try again\n");
    exit(EXIT_FAILURE);
}

/*
 * Slightly modified from StackOverflow user AndiDog:
 * https://stackoverflow.com/questions/918676/generate-sha-hash-in-c-using-openssl-library
 */
int encryption::get_SHA256(void* input, unsigned long length, unsigned char* md)
{
    SHA256_CTX context;
    if(!SHA256_Init(&context))
        return 1;

    if(!SHA256_Update(&context, (unsigned char*)input, length))
        return 1;

    if(!SHA256_Final(md, &context))
        return 1;

    return 0;
}

/*
 * Encrypts plaintext
 */
int encryption::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 == 1) {
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();
  } else {
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handle_errors();
  }


  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handle_errors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   * If error at this stage, throw custom error message
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
      encryption_error();

  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

/*
 * Decrypts plaintext
 */
int encryption::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    decryption_error();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handle_errors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   * Any errors caught here signify an incorrect password, so throw
   * custom error
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) decryption_error();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}
