#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a);

int main(int argc, char **argv){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *e = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *n = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *d = BN_new(); //Ιδιωτικό κλειδί (d, n)
	BIGNUM *M1 = BN_new(); //Αρχικό μήνυμα
	BIGNUM *M2 = BN_new(); //Τροποποιημένο μήνυμα
	BIGNUM *M1_sign = BN_new(); //Αρχικό μήνυμα υπογεγραμμένο
	BIGNUM *M2_sign = BN_new(); //Τροποποιημένο μήνυμα υπογεγραμμένο

	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&M1, "4D657373616765207265636569766564"); // "Message received" σε δεκαεξαδική μορφή
	BN_hex2bn(&M2, "4D657373616765207265636569766566"); // "Message receivef" σε δεκαεξαδική μορφή
	
	//Ομοίως της προηγούμενης δραστηριότητας κάνουμε μέσω της παρακάτω συνάρτησης: Mx_sign = Mx ^ d mod n
	BN_mod_exp(M1_sign, M1, d, n , ctx);
	BN_mod_exp(M2_sign, M2, d, n , ctx);

	printf("\n===================================================================================-\n");
	printBN("Μήνυμα 1: ", M1);
	printBN("Μήνυμα 2: ", M2);
	printBN("Μήνυμα 1 υπογεγραμμένο: ", M1_sign);
	printBN("Μήνυμα 2 υπογεγραμμένο: ", M2_sign);
	printf("===================================================================================-\n");
	fflush(stdout);
	return 0;
}

void printBN(char *msg, BIGNUM * a){
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	fflush(stdout);
	OPENSSL_free(number_str);
}