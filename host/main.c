
#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <tee_client_api.h>

#include <ta_socket.h>

#define MAX 256
#define PORT 8080 
#define SA struct sockaddr 
#define TEST_EN_DE_CRYPT_COMMAND 0
#define TEST_ENCRYPT_IN_TA_COMMAND 1
#define TEST_DECRYPT_IN_TA_COMMAND 2

#define BOOLEAN int
#define TRUE (1==1)
#define FALSE !TRUE

void encrypt_in_secure_world (char *);
void decrypt_in_secure_world (uint8_t *, uint8_t *);
BOOLEAN encrypt_using_private_key (char * in, int in_len, char * out, int * out_len);
BOOLEAN decrypt_using_public_key (uint8_t * in, int in_len, uint8_t * out, int * out_len);

// check your return code
void check_rc (TEEC_Result rc, const char *errmsg, uint32_t *orig) {

   if (rc != TEEC_SUCCESS) {
      fprintf(stderr, "%s: 0x%08x", errmsg, rc);
      if (orig)
      fprintf(stderr, " (orig=%d)", (int)*orig);
      fprintf(stderr, "\n");

      exit(1);
   }
}

RSA *createRSA(unsigned char *key, int public);

// global variables
char public_key[] =
"-----BEGIN PUBLIC KEY-----\n"
"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL5c51/v1osjr5+lRPykmpQKyGdXMG0g\n"
"S6Du1l8Hm0qYXc+azq6qqZvr39zeufw/VLKTfeKeKVJX1D28TImn6cUCAwEAAQ==\n"
"-----END PUBLIC KEY-----\n";

char private_key[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIBOgIBAAJBAL5c51/v1osjr5+lRPykmpQKyGdXMG0gS6Du1l8Hm0qYXc+azq6q\n"
"qZvr39zeufw/VLKTfeKeKVJX1D28TImn6cUCAwEAAQJASDCJGculK6zDzCHrkHeH\n"
"mz6fkvjwh2Go7IXGS9FhpZ6Lx6FacvAEyARdXlIYXNRogiEX3aHMQoflhOFYIMID\n"
"fQIhAPj4koWd11bSLeR5bI1ojNm/M7y6oKYiWlX/Txbo66L7AiEAw7y+czu2VIdK\n"
"qcUfGnLfI9qVrZPhw4rB14/3oOBXCj8CIQC5yINNwaLW3q/wNcuTGdlBAzSQOJN4\n"
"ZVoTohhaeCSd0QIgGqi0T8GMPcsHckP0zodiuOFmjXOcxiM574AeO/0SHcUCICkw\n"
"Ztd6hrPK/M6HFQL/fGu1MecHNrsKyroMlZNqLmXu\n"
"-----END RSA PRIVATE KEY-----\n";

char tmp[256] = "";
int tmp_len;

void encrypt_in_secure_world (char *buff) {

   char test_in [] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
   int test_in_len = strlen (test_in);

   char test_decrypted [256] = "";
   int test_decrypted_len;

   TEEC_Result rc;
   TEEC_Context ctx;
   TEEC_Session sess;
   TEEC_Operation op;
   TEEC_SharedMemory field_in;
   TEEC_SharedMemory field_back;
   TEEC_SharedMemory field_ticket;
   TEEC_UUID uuid =  TA_SOCKET_UUID;
   uint32_t err_origin;

   // header
   printf("<<<<<<<<<<<<<<<<<<<<<<<<<<< test_encrypt_secure_world >>>>>>>>>>>>>>>>>>>>>>>>>\n");

   /* Initialize a context connecting us to the TEE */
   rc = TEEC_InitializeContext(NULL, &ctx);
   check_rc(rc, "TEEC_InitializeContext", NULL);

   // open a session to the TA
   rc = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
   check_rc(rc, "TEEC_OpenSession", &err_origin);

   // ok, create the needed shared memory blocks we will be using later
   //field_in.buffer = NULL;
   field_in.buffer = calloc(sizeof(buff), sizeof(char));
   field_in.flags = TEEC_MEM_INPUT;
   field_in.size = sizeof(buff);
   memcpy(field_in.buffer, buff, sizeof(buff));
   rc = TEEC_AllocateSharedMemory(&ctx, &field_in);
   check_rc(rc, "TEEC_AllocateSharedMemory for field_in", NULL);
   
   // field back
   field_back.buffer = NULL;
   field_back.size = 256;
   field_back.flags = TEEC_MEM_OUTPUT;
   rc = TEEC_AllocateSharedMemory(&ctx, &field_back);
   check_rc(rc, "TEEC_AllocateSharedMemory for field_back", NULL);

   /* Clear the TEEC_Operation struct */
   memset(&op, 0, sizeof(op));

   // assign param
   op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE);
   op.params[0].memref.parent = &field_in;
   op.params[0].memref.size = field_in.size;
   op.params[1].memref.parent = &field_back;

   // prepare for encrypt
   printf ("\n");
   printf ("Encrypt in secure world test\n");
   printf ("\n");
   memcpy(field_in.buffer, test_in, test_in_len);
   rc = TEEC_InvokeCommand(&sess, TEST_ENCRYPT_IN_TA_COMMAND, &op, &err_origin);
   check_rc(rc, "TEEC_InvokeCommand", &err_origin);
   printf ("Origional string (26 chars):  %s\n", (char *)buff);
   printf ("Origional string len:         %i\n", test_in_len);
   printf ("SW Encryted value:            %s\n", (char *) field_back.buffer);
   printf ("SW Encryted len:              %i\n", (int) field_back.size);
   printf ("\n");
   printf("<<<<<<<<<<<<<<<<<<<<<<<<<<< end of test >>>>>>>>>>>>>>>>>>>>>>>>\n");
   // clean up once you have finished
   printf("Cleaning up after yourself\n");
   TEEC_CloseSession(&sess);
   TEEC_FinalizeContext(&ctx);
}

// send something encrypted to the secure world for decryption
void decrypt_in_secure_world (uint8_t *buff, uint8_t *digest) {

   char test_in [] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
   int test_in_len = strlen (test_in);

   char test_encrypted [256] = "";
   int test_encrypted_len;

   TEEC_Result rc;
   TEEC_Context ctx;
   TEEC_Session sess;
   TEEC_Operation op;
   TEEC_SharedMemory field_in;
   TEEC_SharedMemory field_back;
   TEEC_SharedMemory field_ticket;
   TEEC_UUID uuid = TA_SOCKET_UUID;
   uint32_t err_origin;
   
   const char *en_tmp = buff;

   uint8_t en[64];
   for (size_t count = 0; count < sizeof en/sizeof *en; count++) {
        sscanf(en_tmp, "%2hhx", &en[count]);
        printf("%x ",en[count]);
        en_tmp += 2;
    }

   printf("======================================================\n");
   const char *pos = digest;

   uint8_t val[20];
   for (size_t count = 0; count < sizeof val/sizeof *val; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        printf("%x ",val[count]);
        pos += 2;
    }
   printf("\n");
   printf(">>>>>>>>>>>>>>>>>>\n");
   // header
   printf("<<<<<<<<<<<<<<<<<<<<<<<<<<< test_decrypt_secure_world >>>>>>>>>>>>>>>>>>>>>>>>>\n");

   /* Initialize a context connecting us to the TEE */
   rc = TEEC_InitializeContext(NULL, &ctx);
   check_rc(rc, "TEEC_InitializeContext", NULL);

   // open a session to the TA
   rc = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
   check_rc(rc, "TEEC_OpenSession", &err_origin);
   
   // ok, create the needed shared memory blocks we will be using later
   field_in.buffer = NULL;
   field_in.size = 64; /////// sizeof(buff) 64
   field_in.flags = TEEC_MEM_INPUT;
   rc = TEEC_AllocateSharedMemory(&ctx, &field_in);
   check_rc(rc, "TEEC_AllocateSharedMemory for field_in", NULL);
   
   // field back
   field_back.buffer = NULL;
   field_back.size = 20; /////////////// sizeof (val)
   field_back.flags = TEEC_MEM_INPUT;
   rc = TEEC_AllocateSharedMemory(&ctx, &field_back);
   check_rc(rc, "TEEC_AllocateSharedMemory for field_back", NULL);

   field_ticket.buffer = NULL;
   field_ticket.size = 64; /////////////// sizeof (val)
   field_ticket.flags = TEEC_MEM_OUTPUT;
   rc = TEEC_AllocateSharedMemory(&ctx, &field_ticket);
   check_rc(rc, "TEEC_AllocateSharedMemory for field_back", NULL);

   /* Clear the TEEC_Operation struct */
   memset(&op, 0, sizeof(op));

   // assign param
   op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE);
   op.params[0].memref.parent = &field_in;
   op.params[1].memref.parent = &field_back;
   op.params[2].memref.parent = &field_ticket;

   // prepare for encrypt
   printf ("\n");
   printf ("Decrypt in secure world test\n");
   printf ("\n");
   memcpy(field_in.buffer, buff, 64); //64
   memcpy(field_back.buffer, val, 20);
   //memcpy(field_ticket.buffer, val, 64);

   op.params[0].memref.size = 64;
   op.params[1].memref.size = 20;
   op.params[2].memref.size = 64;

   // decrypt in TA
   rc = TEEC_InvokeCommand(&sess, TEST_DECRYPT_IN_TA_COMMAND, &op, &err_origin); /////////////////////////////////////////////
   printf ("%x\n",(uint8_t *)field_ticket.buffer);
   printf ("%x\n",(uint8_t)field_ticket.buffer);
   printf ("%x\n",field_ticket.buffer);
   printf ("%s\n",(char *)field_ticket.buffer);
   printf ("\n");
   printf("<<<<<<<<<<<<<<<<<<<<<<<<<<< end of test >>>>>>>>>>>>>>>>>>>>>>>>\n");
   // clean up once you have finished
   printf("Cleaning up after yourself\n");
   TEEC_CloseSession(&sess);
   TEEC_FinalizeContext(&ctx);
}

void erase(char *str, char ch){
	for(;*str!='\0';str++){
		if(*str==ch){
			strcpy(str,str+1);
			str--;
		}
	}
}

// Function designed for chat between client and server. 
void func(int sockfd) 
{ 
    uint8_t buff[MAX]; 
    int n; 
    // infinite loop for chat 
    for (;;) {
	printf("start\n");
	uint8_t buff[MAX];
	
        bzero(buff, MAX); 
        read(sockfd, buff, sizeof(buff)); 
	//erase(buff, '0');
	//erase(buff, ' ');
	//erase(buff, '\n');
        //printf("%s\n", buff);
	if (strncmp("exit", buff, 4) == 0) { 
            printf("Server Exit...\n"); 
            break; 
        }
	else if (strncmp("result", buff, 6) == 0) {
		printf("%s\n", buff);
		char *tmp;
		FILE *fp = NULL;
		fp = fopen("test.txt","r");
		fseek(fp,0,SEEK_END);
		int size = ftell(fp);
		tmp = malloc(size+1);
		memset(tmp,0,size+1);
		fseek(fp, 0, SEEK_SET);
		//int count = fread(tmp, size, 1, fp);
		write(sockfd, tmp, size);
		fclose(fp);
		free(tmp);
		printf(">>>>>>>>>>>>>>>>>>\n");
        } 
 
	else { 
		for(int i = 0 ; i < sizeof(buff);i++){
			printf("%x ",buff[i]);
		}
                printf("\n");
		uint8_t digest[MAX];
        	bzero(digest, MAX); 
        	read(sockfd, digest, sizeof(digest));
                for(int i = 0 ; i < sizeof(digest);i++){
			printf("%x ",digest[i]);
		}
                printf("\n");
                printf("%s\n", digest);
		//encrypt_in_secure_world(buff);
		decrypt_in_secure_world(buff,digest);
		}
	printf("end\n");
    }
    printf("eeeeeeeeeeeeeeeeeend\n");
} 
  
// Driver function 
int main() 
{ 
    int sockfd, connfd, len; 
    struct sockaddr_in servaddr, cli; 
  
    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(22); 
  
    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully binded..\n"); 
  
    // Now server is ready to listen and verification 
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listen failed...\n"); 
        exit(0); 
    } 
    else
        printf("Server listening..\n"); 
    len = sizeof(cli); 
  
    // Accept the data packet from client and verification 
    connfd = accept(sockfd, (SA*)&cli, &len); 
    if (connfd < 0) { 
        printf("server acccept failed...\n"); 
        exit(0); 
    } 
    else
        printf("server acccept the client...\n"); 

    int bufSize = 4096;
    setsockopt(connfd, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize));
    // Function for chatting between client and server 
    func(connfd); 
  
    // After chatting close the socket 
    close(sockfd); 
} 

