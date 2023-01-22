// This Program ecrypts the input message given by terminal run on Linux as:
// python3 -c 'print("<message>".encode("utf-8").hex())'

#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a);
void PrivKeyCalc(BIGNUM *d, BIGNUM *p, BIGNUM *q, BIGNUM *e);

int main(int argc, char **argv){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *n = BN_new(); //Δημόσιο κλειδί (e, n)
	BIGNUM *d = BN_new(); //Ιδιωτικό κλειδί (d, n)
	BIGNUM *name = BN_new(); 
	BIGNUM *C = BN_new();
	BIGNUM *M = BN_new();
	
	//Αρχικοποίηση κλειδιών
	BN_hex2bn(&p, "953AAB9B3F23ED593FBDC690CA10E703");
	BN_hex2bn(&q, "C34EFC7C4C2369164E953553CDF94945");
	BN_hex2bn(&e, "0D88C3");
	BN_mul(n, p, q, ctx);
	PrivKeyCalc(d, p, q, e);
	
	BN_hex2bn(&name, "4d61726b6f732050616e74656c6964616b6973"); //"Markos Pantelidakis" σε δεκαεξαδική μορφή
	
	BN_mod_exp(C, name, e, n, ctx); //Κρυπτογραφιμένο μήνυμα (C): encrypted message = name ^ e mod n
	BN_mod_exp(M, C, d, n, ctx); // Κρυπτογραφιμένο μήνυμα (M): decrypted message = (encrypted message) ^ d mod n
	
	printf("\n=====================================================================================\n");
	printf("Ονοματεπώνυμο (ASCII): Markos Pantelidakis\n");
	printBN("Ονοματεπώνυμο σε δεκαεξαδικό: ", name);
	printBN("\nΚρυπτογραφιμένο όνομα: ", C);
	printBN("Απορυπτογραφιμένο όνομα: ", M);
	printf("======================================================================================\n");
		
	fflush(stdout);
	return 0;
}

void printBN(char *msg, BIGNUM * a){
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	fflush(stdout);
	OPENSSL_free(number_str);
}

void PrivKeyCalc(BIGNUM *d, BIGNUM *p, BIGNUM *q, BIGNUM *e){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *one = BN_new();
	BIGNUM *val_p = BN_new();
	BIGNUM *val_q = BN_new();
	
	BN_hex2bn(&one, "1");
	BN_sub(val_p, p, one); //val_p = p-1
	BN_sub(val_q, q, one); //val_q = q-1
	BN_mul(val_p, val_p, val_q, ctx); //val_p = val_p * val_q - Χρήση val_p για την αποθήκευση του γινομένου
	BN_mod_inverse(d, e, val_p, ctx); //e*d mod(p-1)*(q-1) = 1
	
	OPENSSL_free(ctx);
	OPENSSL_free(one);
	OPENSSL_free(val_p);
	OPENSSL_free(val_q);
}