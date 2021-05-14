#include "sender.h"
#define SEED_LEN 128

int n, d, e;//(n, e) is RSA public key. (n, d) is private key
void sendInteger(int sock, int num);
int receiveInteger(int sock);
bool isPrime(int n);
void my_RSA_generate_key();//generate public key and private key
int my_RSA_decrypt_char(int c, int d, int n);//decrypt single char
void my_RSA_private_decrypt(int length, int* src, unsigned char* dst);//decrypt string

int main(){
    int serv_sock=getServerSocket("192.168.142.128",8000);
    printf("Sender socket ready.\n");
    printf("Waiting for connection...\n");
    int clnt_sock=waitForConnection(serv_sock);
    printf("Connection built.\n");
    
    //generate and print RSA key
    my_RSA_generate_key();
    printf("The public key is n = %d, e = %d.\n", n, e);
    
    //send RSA public key to receiver
    sendInteger(clnt_sock, n);
    sendInteger(clnt_sock, e);
    printf("You can compare this with the public key on the receiver.\n");
    
    //receive the encrypted seed.
    int buffer[SEED_LEN];
    unsigned char *s_b = (unsigned char *)buffer;
    recvSeed(s_b, SEED_LEN * sizeof(int), clnt_sock);
    printf("The encrypted seed is %d\n", buffer[0]);
    
    //decrypt the seed.
    unsigned char outseed[SEED_LEN];
    memset(outseed, 0, sizeof(outseed));
    my_RSA_private_decrypt(SEED_LEN, buffer, outseed);
    printf("The origin seed is %s\n", outseed);
    
    /*
    //1024-bits,RSA_F4-e_value,no callback
    RSA *ClientRSA=RSA_generate_key(1024, RSA_F4, NULL, NULL);
    //print the rsa.
    RSA_print_fp(stdout,ClientRSA,0);
    unsigned char PublicKey[1024];
    unsigned char *PKey=PublicKey;
    //Extract the public key information into buffer. In case of changes on the PublicKey, we use pointer PKey.
    int PublicKeyLen=i2d_RSAPublicKey(ClientRSA, &PKey);
    //print public key length, needed later.
    printf("PublicKeyBuff, Len=%d\n", PublicKeyLen);
    //print public key information for comparison
    for (int i=0; i<PublicKeyLen; i++)
    {
        printf("0x%02x, ", *(PublicKey+i));
    }
    printf("\n");
    //send public key information and key length to receiver.
    sendKey(PublicKey,PublicKeyLen,clnt_sock);
    //Again, for comparison.
    PKey = PublicKey;
    RSA *EncryptRsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&PKey, PublicKeyLen);
    printf("You can compare this with the public key on the receiver.\n");
    RSA_print_fp(stdout,EncryptRsa,0);
    //receive the encrypted seed.
    unsigned char buffer[128];
    unsigned char *s_b=buffer;
    recvSeed(s_b,128,clnt_sock);
    printf("The encrypted seed is %s\n",buffer);
    //decrypt the seed.
    unsigned char outseed[128];
    memset(outseed, 0, sizeof(outseed));
    RSA_private_decrypt(128, (const unsigned char*)buffer, outseed, ClientRSA, RSA_NO_PADDING);
    printf("The origin seed is %s\n",outseed);
    */
    
    
    //aes-key
    unsigned char aesSeed[32]; //If you use no-padding while encrypting the origin seed, it must be 128bytes, but we only need the first 32bytes.
    strncpy((char*)aesSeed,(const char*)outseed,32);
    AES_KEY AESEncryptKey;
    AES_set_encrypt_key(aesSeed, 256, &AESEncryptKey);
    printf("Negotiation completes.\n");
    unsigned char path[4097];
    unsigned char fname[4097];
    unsigned char data_to_encrypt[16];
    unsigned char data_after_encrypt[16];
    unsigned char *dae;
    unsigned long fsize;
    while(1){
        memset(path,0,sizeof(path));
        printf("Please input path of the file you wanna send:\n");
        scanf("%s",path);
        FILE* fp;
        while((fp=fopen((const char*)path,"rb"))==NULL){
            memset(path,0,sizeof(path));
            printf("File error!\n");
            printf("Please input path of the file you wanna send:\n");
            scanf("%s",path);
        }
        printf("File opening...\n");
        fseek(fp,SEEK_SET,SEEK_END);
        fsize=ftell(fp);
        fseek(fp,0,SEEK_SET);
        memset(data_to_encrypt,0,sizeof(data_to_encrypt));
        sendFile(fp,fsize,path,data_to_encrypt,data_after_encrypt,&AESEncryptKey,clnt_sock);
        fclose(fp);
    }
    //RSA_free(ClientRSA);
    //RSA_free(EncryptRsa);
    
    close(serv_sock);
    return 0;
}

void my_RSA_private_decrypt(int length, int* src, unsigned char* dst) {
    for(int i = 0; i < length; i++) {
        dst[i] = (char)(my_RSA_decrypt_char(src[i], d, n));
    }
}

void sendInteger(int sock, int num) {
    char* data = (char*)(&num);
    write(sock, data, sizeof(int));
}

int receiveInteger(int sock) {
    int res;
    char* data = (char*)(&res);
    read(sock, data, sizeof(int));
    return res;
}

void my_RSA_generate_key() {
    int p, q;
    do {
        p = rand() % 200;
    } while(!isPrime(p) || p < 20);
    do {
        q = rand() % 200;
    } while(!isPrime(q) || q < 20 || p == q);
    
    printf("p = %d, q = %d\n", p, q);
    
    n = p * q;
    int fn = (p - 1) * (q - 1);
    printf("n = %d, fn = %d\n", n, fn);
    
    do {
        e = rand() % 40000;
    } while(!isPrime(e) || e <= 1 || e >= n);
    
    printf("e = %d\n", e);
    
    d = 1;
    while((e * d - 1) % fn != 0) {
	d++;
    }
    
    printf("d = %d\n", d);
    
    
    /*
    n = 3233;
    e = 17;
    d = 2753;
    */
}

int my_RSA_decrypt_char(int c, int d, int n) {
    int m = 1;
    for(int i = 0; i < d; i++) {
	m = (m * c) % n;
    }
    return m;
}

bool isPrime(int n) {
    if(n < 2) {
    	return false;
    }
    for(int i = 2; i * i <= n; i++) {
    	if(n % i == 0) {
    	    return false;
    	}
    }
    return true;
}
