#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/time.h>
#include "myinterface.h"

#define KEY_LENGTH 16
#define IV_LENGTH 1024


using namespace std;

int main (void)
{
    int fileSize = 0;
    // Must support ECB/CBC/CTR e_or_ds
    const EVP_CIPHER* (*crypo_algm)(void) = NULL;
    /* A 128 bit key */
    unsigned char *key = NULL;
    key = (unsigned char*)malloc(KEY_LENGTH);
    memcpy(key, (unsigned char *)"6789012345678900", KEY_LENGTH);


    /* A 128 bit IV */
    unsigned char *iv = NULL;
    iv = (unsigned char*)malloc(IV_LENGTH);
    memcpy(iv, (unsigned char *)"0123456789012345", IV_LENGTH);

    char answer_tmp[100], filename[256];

    int e_or_d=0, mode = 0;

    memset(answer_tmp, '0', sizeof(answer_tmp));

    printf("(1) Which function do you want to use?  (1)Encryption (2)Decryption \n > ");
    scanf("%s", answer_tmp);

    e_or_d = atoi(answer_tmp);

    while(e_or_d!=1 && e_or_d!=2){
        fprintf(stderr,"Please Enter a number in range of 1~2: \n");
        scanf("%s", answer_tmp);
        e_or_d = atoi(answer_tmp);
    }

    printf("(2) Which mode do you want to use?  (1)ECB (2)CBC (3)CTR \n > ");
    scanf("%s", answer_tmp);

    mode = atoi(answer_tmp);

    while(mode<1 || mode>3){
        fprintf(stderr,"Please Enter a number in range of 1~3: \n > ");
        scanf("%s", answer_tmp);
        mode = atoi(answer_tmp);
    }

    switch(mode)
    {
        case 1:
            crypo_algm = EVP_aes_128_ecb;
            break;
        case 2:
            crypo_algm = EVP_aes_128_cbc;
            break;
        case 3:
            crypo_algm = EVP_aes_128_ctr;
            break;
    }


    printf("(3) Please Enter %d bits Key. \n   Hint: If You don't want to enter, enter \"0\" to use the key [%s] by default. \n > ",KEY_LENGTH,key);
    scanf("%s", answer_tmp);

    // printf("Len: %ld", strlen(answer_tmp));


    if(strcmp(answer_tmp,"0")!=0)
    {
        while(strlen(answer_tmp)!=KEY_LENGTH){
            fprintf(stderr,"Please Enter %d bits Key.  \n > ", KEY_LENGTH);
            scanf("%s", answer_tmp);
        }

        memcpy(key, (unsigned char *) answer_tmp, KEY_LENGTH);
    }

    printf("Your key is %s\n", key);

    if(mode==2||mode==3)
    {
        printf("(4)You can enter initial vector.\n");
        printf("   Hint: If You don't want to enter, enter \"0\" to use the IV [%s] by default. \n > ", iv);
        scanf("%s", answer_tmp);

        if(strcmp(answer_tmp,"0")!=0)
        {
            memset(iv,'\0',sizeof(iv));
            memcpy(iv, (unsigned char *) answer_tmp, strlen(answer_tmp));
        }

        
        printf("Your IV is %s\n", iv);
    }



    printf("(5)Please enter filename.\n");
    scanf("%s", filename);


    
    struct timeval start, end;
    gettimeofday( &start, NULL );


    if(e_or_d==1)
        fileSize = encrypt(filename, crypo_algm, key, iv);
    else if(e_or_d==2)
        fileSize = decrypt(filename, crypo_algm, key, iv);


    gettimeofday( &end, NULL );
    int timeuse = 1000000 * ( end.tv_sec - start.tv_sec ) + end.tv_usec - start.tv_usec;
    printf("Spend Time:\t %d us\n", timeuse);

    printf("File Size:\t %d Byte\n", fileSize);

    printf("Performance:\t %.2f MB/s", (float)fileSize/(float)timeuse);

    return 0;
}