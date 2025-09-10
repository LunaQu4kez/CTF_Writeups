#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#define SM2LEN 32

int error() {
    printf("Error.\n");
    return 0;
}

int error_partial_verify() {
    printf("Error partial verify.\n");
    return 0;
}

void print_flag2(const BIGNUM *d2) {
    char *hex_str = BN_bn2hex(d2);
    for (int i = 0; hex_str[i] != '\0'; i++) {
        if (hex_str[i] >= 'A' && hex_str[i] <= 'F') {
            hex_str[i] += 32;
        }
    }
    printf("flag2{%s}\n", hex_str);
}

typedef struct {
    char s2[SM2LEN * 2 + 1];
    char s3[SM2LEN * 2 + 1];
    char r[SM2LEN * 2 + 1];
    int success;
} Result;

// 协同签名服务端签名算法
Result server(char* str_e,char* str_p1x,char* str_p1y,char* str_q1x,char* str_q1y,char* str_r1,char* str_s1){
    Result res = {"", "", "", 0};

	int rv = 1;
	BIGNUM *e,*a,*b,*p,*n,*x,*y;
	BIGNUM *d2,*r1,*s1,*p1x,*p1y,*q1x,*q1y;
	BIGNUM *u1,*u2,*xprime,*yprime,*k2,*k3,*x1,*y1,*r,*s2,*s3,*s,*tmp1,*tmp2,*tmp3;
	EC_GROUP* group;
	EC_POINT *generator,*G,*P,*P1,*Q1,*TMP;

	BN_CTX* bn_ctx = BN_CTX_new();
	BN_CTX_start(bn_ctx);
	if (!bn_ctx)
		{ error(); return res; }
	e = BN_CTX_get(bn_ctx);
	a = BN_CTX_get(bn_ctx);
	b = BN_CTX_get(bn_ctx);
	p = BN_CTX_get(bn_ctx);
	n = BN_CTX_get(bn_ctx);
	d2 = BN_CTX_get(bn_ctx);
	x = BN_CTX_get(bn_ctx);
	y = BN_CTX_get(bn_ctx);
	p1x = BN_CTX_get(bn_ctx);
	p1y = BN_CTX_get(bn_ctx);
	q1x = BN_CTX_get(bn_ctx);
	q1y = BN_CTX_get(bn_ctx);
	r1 = BN_CTX_get(bn_ctx);
	s1 = BN_CTX_get(bn_ctx);
	u1 = BN_CTX_get(bn_ctx);
	u2 = BN_CTX_get(bn_ctx);
	xprime = BN_CTX_get(bn_ctx);
	yprime = BN_CTX_get(bn_ctx);
	k2 = BN_CTX_get(bn_ctx);
	k3 = BN_CTX_get(bn_ctx);
	x1 = BN_CTX_get(bn_ctx);
	y1 = BN_CTX_get(bn_ctx);
	r = BN_CTX_get(bn_ctx);
	s2 = BN_CTX_get(bn_ctx);
	s3 = BN_CTX_get(bn_ctx);
	s = BN_CTX_get(bn_ctx);
	tmp1 = BN_CTX_get(bn_ctx);
	tmp2 = BN_CTX_get(bn_ctx);
	tmp3 = BN_CTX_get(bn_ctx);

	if (
		!BN_hex2bn(&e, str_e) ||
		!BN_hex2bn(&p1x, str_p1x) ||
		!BN_hex2bn(&p1y, str_p1y) ||
		!BN_hex2bn(&q1x, str_q1x) ||
		!BN_hex2bn(&q1y, str_q1y) ||
		!BN_hex2bn(&r1, str_r1) ||
		!BN_hex2bn(&s1, str_s1) ||
		!BN_hex2bn(&a, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC") ||
		!BN_hex2bn(&b, "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93") ||
		!BN_hex2bn(&p, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF") ||
		!BN_hex2bn(&n, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123") ||
		// d2 = ds (server key)
		!BN_hex2bn(&d2, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX") ||
		!BN_hex2bn(&x, "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7") ||
		!BN_hex2bn(&y, "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0") ||
		!BN_rand_range(k2,n) ||
		!BN_copy(k3, k2)
		)
		{ error(); return res; }

    // generate k2 in [1, n-1]
	while(BN_is_zero(k2)){
        if (
            !BN_rand_range(k2,n) ||
            !BN_copy(k3, k2)
            )
            { error(); return res; }
	}

	group = EC_GROUP_new_curve_GFp(p, a, b, bn_ctx);
	generator = EC_POINT_new(group);
	if (!generator)
		{ error(); return res; }
	if (1 != EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, bn_ctx))
		{ error(); return res; }
	if (1 != EC_GROUP_set_generator(group, generator, n, NULL))
		{ error(); return res; }

	G = EC_POINT_new(group);
	P = EC_POINT_new(group);
	P1 = EC_POINT_new(group);
	Q1 = EC_POINT_new(group);
	TMP = EC_POINT_new(group);

    // if r1=0 or s1=0, error
	if (BN_is_zero(r1) || BN_is_zero(s1))
		{ error(); return res; }

	// set P1 = (p1x, p1y)
	if (1 != EC_POINT_set_affine_coordinates_GFp(group, P1, p1x, p1y, bn_ctx))
		{ error(); return res; }

	// set Q1 = (q1x, q1y)
	if (1 != EC_POINT_set_affine_coordinates_GFp(group, Q1, q1x, q1y, bn_ctx))
		{ error(); return res; }

	//u1 = e * (s1^(-1)) mod n, u2 = r1 * (s1^(-1)) mod n
	if (!BN_mod_inverse(tmp1, s1, n, bn_ctx) ||
		!BN_mod_mul(u1, e, tmp1, n, bn_ctx) ||
		!BN_mod_mul(u2, r1, tmp1, n, bn_ctx) ||
		!BN_mod(u1, u1, n, bn_ctx) ||
		!BN_mod(u2, u2, n, bn_ctx)
		)
		{ error(); return res; }

	//u1*G + u2*P1 = (x', y')
	if (!EC_POINT_mul(group, TMP, u1, P1, u2, bn_ctx))
		{ error(); return res; }

	if (!EC_POINT_get_affine_coordinates_GFp(group, TMP, xprime, yprime, bn_ctx))
		{ error(); return res; }

	//verify r1 = x' mod n
	if (!BN_mod(xprime, xprime, n, bn_ctx))
		{ error(); return res; }

	if(BN_cmp(r1,xprime))
		{ error_partial_verify(); return res; }

	//k2*G + k3*Q1 = (x1, y1)
	if (!EC_POINT_mul(group, TMP, k2, Q1, k3, bn_ctx))
		{ error(); return res; }

	if (!EC_POINT_get_affine_coordinates_GFp(group, TMP, x1, y1, bn_ctx))
		{ error(); return res; }

	//r=(e+x1) mod n
	if (!BN_mod_add(r, e, x1, n, bn_ctx))
		{ error(); return res; }

	if (BN_is_zero(r))
		{ error(); return res; }
	strncpy(res.r, BN_bn2hex(r), 2*SM2LEN+1);

	//s2 = d2 * k3 mod n, s3 = d2 * (r+k2) mod n
	if (!BN_mod_mul(s2, d2, k3, n, bn_ctx) ||
		!BN_mod_add(tmp1, r, k2, n, bn_ctx) ||
		!BN_mod_mul(s3, d2, tmp1, n, bn_ctx) ||
		!BN_mod(s2, s2, n, bn_ctx) ||
		!BN_mod(s3, s3, n, bn_ctx)
		)
		{ error(); return res; }
	printf("s2: %s\n",BN_bn2hex(s2));
	printf("s3: %s\n",BN_bn2hex(s3));
	strncpy(res.s2, BN_bn2hex(s2), 2*SM2LEN+1);
	strncpy(res.s3, BN_bn2hex(s3), 2*SM2LEN+1);

    // flag2 的格式如下：flag2{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}，大括号中的内容为 16 进制格式（字母小写）的 d2。
    print_flag2(d2);

    rv = 0;
    BN_CTX_free(bn_ctx);

    return rv;
}

// 计算公钥P
int getPublicKey(char *str_d2, char *str_p1x, char *str_p1y) {
    int rv = 1;
    BIGNUM *negone, *a, *b, *p, *n, *x, *y;
    BIGNUM *d2, *p1x, *p1y, *px, *py;
    BIGNUM *tmp1, *tmp2;
    EC_GROUP *group;
    EC_POINT *generator, *G, *P, *P1;

    BN_CTX *bn_ctx = BN_CTX_new();
    BN_CTX_start(bn_ctx);
    if (!bn_ctx) {
        error();
        return 1;
    }

    negone = BN_CTX_get(bn_ctx);
    a = BN_CTX_get(bn_ctx);
    b = BN_CTX_get(bn_ctx);
    p = BN_CTX_get(bn_ctx);
    n = BN_CTX_get(bn_ctx);
    d2 = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    p1x = BN_CTX_get(bn_ctx);
    p1y = BN_CTX_get(bn_ctx);
    px = BN_CTX_get(bn_ctx);
    py = BN_CTX_get(bn_ctx);
    tmp1 = BN_CTX_get(bn_ctx);
    tmp2 = BN_CTX_get(bn_ctx);

    if (
        !BN_hex2bn(&d2, str_d2) ||
        !BN_hex2bn(&p1x, str_p1x) ||
        !BN_hex2bn(&p1y, str_p1y) ||
        !BN_hex2bn(&a, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC") ||
        !BN_hex2bn(&b, "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93") ||
        !BN_hex2bn(&p, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF") ||
        !BN_hex2bn(&n, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123") ||
        !BN_hex2bn(&x, "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7") ||
        !BN_hex2bn(&y, "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
    ) {
        error();
        return 1;
    }
    group = EC_GROUP_new_curve_GFp(p, a, b, bn_ctx);
    generator = EC_POINT_new(group);
    if (!generator) {
        error();
        return 1;
    }
    if (1 != EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, bn_ctx)) {
        error();
        return 1;
    }
    if (1 != EC_GROUP_set_generator(group, generator, n, NULL)) {
        error();
        return 1;
    }

    G = EC_POINT_new(group);
    P = EC_POINT_new(group);
    P1 = EC_POINT_new(group);

    // set P1 = (p1x, p1y)
    if (1 != EC_POINT_set_affine_coordinates_GFp(group, P1, p1x, p1y, bn_ctx)) {
        error();
        return 1;
    }

    //P = ((d2)^(-1)) * P1 - G
    if (!BN_zero(tmp1) ||
        !BN_one(tmp2) ||
        !BN_mod_sub(negone, tmp1, tmp2, n, bn_ctx)
    ) {
        error();
        return 1;
    }
    if (!BN_mod_inverse(tmp1, d2, n, bn_ctx) || !EC_POINT_mul(group, P, negone, P1, tmp1, bn_ctx)) {
        error();
        return 1;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, P, px, py, bn_ctx)) {
        error();
        return 1;
    }
    printf("Px: %s\n", BN_bn2hex(px));
    printf("Py: %s\n", BN_bn2hex(py));

    rv = 0;
    BN_CTX_free(bn_ctx);

    return rv;
}

int main(int argc, char *argv[]) {
    int rv = 1;
    if (server(argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7])) {
        error();
        return rv;
    }

    rv = 0;
    return rv;
}
