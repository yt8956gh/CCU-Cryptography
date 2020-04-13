#include "myinterface.h"

#define BUFFER_SIZE 1024

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int encrypt(char* filename, const EVP_CIPHER* (*crypo_algm)(void), unsigned char *key, unsigned char *iv)
{
    int count=0, filesize = 0;
    EVP_CIPHER_CTX *ctx;
    char buffer[BUFFER_SIZE*2], filename_out[256];
    unsigned char plaintext[BUFFER_SIZE*2];
    unsigned char ciphertext[BUFFER_SIZE*2];
    int len=0, ciphertext_len=0;
    fstream fileInput, fileOutput;

    fileInput.open(filename, ios::in);

    if (!fileInput.is_open())
    {
        fprintf(stderr, "\"%s\" doesn't exsit.", filename);
        return -1;
    }

    sprintf(filename_out,"de_%s", filename);
    printf("\n\nOutput File:\t %s \n", filename_out);
    fileOutput.open(filename_out,ios::out);

    if (!fileInput.is_open())
    {
        fprintf(stderr, "\"%s\" doesn't exsit.", filename);
        return -1;
    }
    
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, crypo_algm(), NULL, key, iv))
        handleErrors();
        
    do
    {
        fileOutput.write((char *) ciphertext, ciphertext_len);
        fileInput.read(buffer, BUFFER_SIZE);
        buffer[fileInput.gcount()] = '\0';

        filesize+=fileInput.gcount();

        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *) buffer, (int)strlen(buffer)))
            handleErrors();
        ciphertext_len = len;

        ciphertext[ciphertext_len] = '\0';

        count++;
    }while(!fileInput.eof());


    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            handleErrors();

    // printf("<<Redudant: %d>>\n\n", len);    
    ciphertext_len += len; 
    ciphertext[ciphertext_len] = '\0';
    fileOutput.write((char *) ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    fileInput.close();
    fileOutput.close();

    return filesize;
}

int decrypt(char* filename, const EVP_CIPHER* (*crypo_algm)(void), unsigned char *key, unsigned char *iv)
{

    EVP_CIPHER_CTX *ctx;
    char buffer[BUFFER_SIZE*2], filename_out[256];;
    unsigned char plaintext[BUFFER_SIZE*2];
    unsigned char ciphertext[BUFFER_SIZE*2];
    int len=0, plaintext_len=0, filesize=0;
    fstream fileInput, fileOutput;

    

    fileInput.open(filename, ios::in);

    if (!fileInput.is_open())
    {
        fprintf(stderr, "\"%s\" doesn't exsit.", filename);
        return -1;
    }

    sprintf(filename_out,"en_%s", filename);
    printf("\n\nOutput File:\t %s \n", filename_out);
    fileOutput.open(filename_out,ios::out);

    if (!fileInput.is_open())
    {
        fprintf(stderr, "\"%s\" doesn't exsit.", filename_out);
        return -1;
    }

    
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        // printf("EVP_CIPHER_CTX_new\n");
        handleErrors();
    }
        
    if (1 != EVP_DecryptInit_ex(ctx, crypo_algm(), NULL, key, iv))
        handleErrors();
    do
    {
        fileOutput.write((char *) plaintext, plaintext_len);

        fileInput.read(buffer, BUFFER_SIZE);

        filesize+=fileInput.gcount();

        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char *) buffer, fileInput.gcount()))
            handleErrors();
        plaintext_len = len;

        plaintext[plaintext_len] = '\0';

    }while(!fileInput.eof());



    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();

    plaintext_len += len;

    plaintext[plaintext_len] = '\0';

    fileOutput.write((char *) plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return filesize;
}
