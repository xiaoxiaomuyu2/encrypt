#include "receiver.h"

int n, e;
int encode(int m, int e, int n);
void sendInteger(int sock, int num);
int receiveInteger(int sock);
void my_RSA_public_encrypt(int length, unsigned char* src, int* dst);

int main()
{
    //get socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    //connect sender
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;  //ipv4
    serv_addr.sin_addr.s_addr = inet_addr("192.168.142.128");  //ip address
    serv_addr.sin_port = htons(8000);  //port
    int result=connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if(result==-1){
        printf("errno for connection is %d\n",errno);
    }else{
        printf("connection built!\n");
    }
    //try
    int tryReceive = receiveInteger(sock);
    printf("the number is %d!\n", tryReceive);
    n = receiveInteger(sock);
    e = receiveInteger(sock);
    printf("the received public key is n = %d, e = %d.\n", n, e);
    
    unsigned char seed[SEED_LEN];
    int outseed[SEED_LEN];
    unsigned char ranstr[SEED_LEN];
    memset(ranstr,0,128);
    genSeed(ranstr);
    strcpy((char*)seed,(const char*)ranstr);
    my_RSA_public_encrypt(SEED_LEN, seed, outseed);
    printf("The seed is %s\n\n\n\n\n", seed);
    printf("The seed after encryption is %d\n\n\n\n\n", outseed[0]);
    sendSeed((unsigned char*)outseed, SEED_LEN * sizeof(int), sock);
    
    //char c = 'z';
    //sendInteger(sock, encode((int)c, e, n));
    
    /*
    //receive public key and key length
    unsigned char buffer[100000];
    unsigned char *b_f=buffer;
    int32_t pk_len=0;
    recvPKeyAndLen(b_f,&pk_len,sock);

    //print public key information for comparison
    for (int i=0; i<ntohl(pk_len); i++)
    {
        printf("0x%02x, ", *(buffer+i));
    }
    printf("\npklen from server:%d\n",ntohl(pk_len));
    //generate public key
    unsigned char *PKey=buffer;
    RSA *EncryptRsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&PKey, ntohl(pk_len));
    if(EncryptRsa==NULL){
        printf("EncryptRsa error!\n");
    }
    RSA_print_fp(stdout,EncryptRsa,0);

    //encrypt process
    unsigned char seed[SEED_LEN],outseed[SEED_LEN];
    unsigned char ranstr[SEED_LEN];
    memset(ranstr,0,128);
    genSeed(ranstr);
    strcpy((char*)seed,(const char*)ranstr);
    if(RSA_public_encrypt(SEED_LEN, (const unsigned char*)seed, outseed, EncryptRsa, RSA_NO_PADDING)==-1)
    {
        printf("encrypt failed!\n");
        char szErrMsg[1024] = {0};
        printf("error for encrypt is %s\n",ERR_error_string(ERR_get_error(),szErrMsg));
    }
    else{
        printf("The seed length is %d\n", SEED_LEN);
        printf("The seed is %s\n\n\n\n\n",seed);
        printf("The seed after encryption is %s\n\n\n\n\n",outseed);
    }
    //send encrypted seed
    sendSeed(outseed,SEED_LEN,sock);
    */
    
    /*
    unsigned char data_after_encrypt[16];
    unsigned char data_after_decrypt[16];
    unsigned char aesSeed[32];
    strncpy((char*)aesSeed,(const char*)seed,32);
    AES_KEY AESDecryptKey;
    AES_set_decrypt_key(aesSeed, 256, &AESDecryptKey);
    while(1){
        //receive data
        printf("Wainting For File...\n");
        memset(data_after_encrypt,0,sizeof(data_after_encrypt));
        recvFile(data_after_encrypt,data_after_decrypt,&AESDecryptKey,sock);
    }
    RSA_free(EncryptRsa);
    */
    close(sock);
    return 0;
}

void my_RSA_public_encrypt(int length, unsigned char* src, int* dst) {
    for(int i = 0; i < length; i++) {
        dst[i] = encode((int)(src[i]), e, n);
    }
}

int encode(int m, int e, int n) {
	//printf("encode function input: m=%d,e=%d, n=%d\n", m, e, n); 
	int c = 1;
	for(int i = 0; i < e; i++) {
		c = (c * m) % n;
	}
	//printf("encode function output: c=%d\n", c);
	return c;
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
