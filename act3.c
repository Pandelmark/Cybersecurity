#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a);

int main(int argc, char **argv){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *e = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *n = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *d = BN_new(); //Ιδιωτικό κλειδί (d, n)
	BIGNUM *C = BN_new(); // κρυπτογράφημα C
	BIGNUM *dec_C = BN_new(); // αποκρυπτογραφημένο C

	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&C, "B3AF0A70793BB53492B5311AED5EA843D94661924C97A446E9DD75846DF860DF");

	BN_mod_exp(dec_C, C, d, n, ctx); // dec_C = C ^ d mod n
	printf("\n============================================================================================\n");
	printBN("Η αποκρυπτογραφημένη τιμή του C είναι: ", dec_C);
	printf("============================================================================================\n");
	fflush(stdout);
	return 0;
}

void printBN(char *msg, BIGNUM * a){
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	fflush(stdout);
	OPENSSL_free(number_str);
}