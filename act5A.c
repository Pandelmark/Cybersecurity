#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 128

void printBN(char *msg, BIGNUM * a);

int main(int argc, char **argv){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *e = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *n = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *d = BN_new(); //Ιδιωτικό κλειδί (d, n)
	BIGNUM *S = BN_new(); //υπογραφή του Bob
	BIGNUM *S_fake = BN_new(); //ψεύτικη υπογραφή/
	BIGNUM *S_valid = BN_new(); //πιστοποίηση της υπογραφής
	BIGNUM *M = BN_new(); //μήνυμα Μ

	//Αρχικοποίηση
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&M, "4c61756e63682061206d697373696c652e");

	BN_mod_exp(S_valid, S, e, n, ctx); 

	printBN("Η πιστοποιημένη υπογραφή είναι: ", S_valid);
	printBN("\nΗ υπογραφή είναι: ", S);
	
	printf("\n===================================================================================-\n");
	if(BN_cmp(M, S_valid) == 0)
		printf("Launch a missile \n");
	else
		printf("Do not launch any missile. \n");
	printf("===================================================================================-\n");
	fflush(stdout);
	return 0;
}

void printBN(char *msg, BIGNUM * a){
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}