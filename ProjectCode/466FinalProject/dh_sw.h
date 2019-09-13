#include <stdio.h>
#include <string.h>
#include "systemc.h"
#include "digit.h"

#ifndef _DH_SW_H_
#define _DH_SW_H_ 1

#define NUM_KEYEXCHANGE 2
#define KEY_LENGTH 64


/*********************************************************************/

/* POINTER defines a generic pointer type */
typedef unsigned char* POINTER;

//-----------------------------------------
// This is now in digit.h

/* UINT2 defines a two byte word */
//typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
//typedef unsigned long int UINT4;
//-----------------------------------------

#ifndef NULL_PTR
#define NULL_PTR ((POINTER)0)
#endif

#ifndef UNUSED_ARG
#define UNUSED_ARG(x) x = *(&x);
#endif


/*********************************************************************/

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
   rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD5 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD5 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */


 /* MD5 context. */
typedef struct {
	UINT4 state[4];                                   /* state (ABCD) */
	UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;


/* Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

 /* F, G, H and I are basic MD5 functions.
  */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

  /* ROTATE_LEFT rotates x left n bits.
   */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

   /* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
	  Rotation is separate from addition to prevent recomputation.
	*/
#define FF(a, b, c, d, x, s, ac) { \
    (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
    (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
  }


	/*********************************************************************/

	/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
		 Inc., created 1991. All rights reserved.
	 */

	 /* RSA key lengths.
	  */
#define MIN_RSA_MODULUS_BITS 508
#define MAX_RSA_MODULUS_BITS 1024
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)

	  /* Maximum length of Diffie-Hellman parameters.
	   */
#define DH_PRIME_LEN(bits) (((bits) + 7) / 8)

	   /* Error codes.
		*/
#define RE_DATA 0x0401
#define RE_NEED_RANDOM 0x0408


		/* Random structure.
		 */
typedef struct {
	unsigned int bytesNeeded;
	unsigned char state[16];
	unsigned int outputAvailable;
	unsigned char output[16];
} R_RANDOM_STRUCT;

/* RSA public and private key.
 */
typedef struct {
	unsigned int bits;                           /* length in bits of modulus */
	unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
	unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
} R_RSA_PUBLIC_KEY;

typedef struct {
	unsigned int bits;                           /* length in bits of modulus */
	unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
	unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     /* public exponent */
	unsigned char exponent[MAX_RSA_MODULUS_LEN];          /* private exponent */
	unsigned char prime[2][MAX_RSA_PRIME_LEN];               /* prime factors */
	unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];   /* exponents for CRT */
	unsigned char coefficient[MAX_RSA_PRIME_LEN];          /* CRT coefficient */
} R_RSA_PRIVATE_KEY;

/* RSA prototype key.
 */
typedef struct {
	unsigned int bits;                           /* length in bits of modulus */
	int useFermat4;                        /* public exponent (1 = F4, 0 = 3) */
} R_RSA_PROTO_KEY;

/* Diffie-Hellman parameters.
 */
typedef struct {
	unsigned char* prime;                                            /* prime */
	unsigned int primeLen;                                 /* length of prime */
	unsigned char* generator;                                    /* generator */
	unsigned int generatorLen;                         /* length of generator */
} R_DH_PARAMS;


/*********************************************************************/

//---------------------------------------------------------------------
// This is now in digit.h

// typedef UINT4 NN_DIGIT;
// typedef UINT2 NN_HALF_DIGIT;

/* Constants.

   Note: MAX_NN_DIGITS is long enough to hold any RSA modulus, plus
   one more digit as required by R_GeneratePEMKeys (for n and phiN,
   whose lengths must be even). All natural numbers have at most
   MAX_NN_DIGITS digits, except for double-length intermediate values
   in NN_Mult (t), NN_ModMult (t), NN_ModInv (w), and NN_Div (c).
 */
 /* Length of digit in bits */
 //#define NN_DIGIT_BITS 32
 //#define NN_HALF_DIGIT_BITS 16
 /* Length of digit in bytes */
 //#define NN_DIGIT_LEN (NN_DIGIT_BITS / 8)
 /* Maximum length in digits */
 //#define MAX_NN_DIGITS ((MAX_RSA_MODULUS_LEN + NN_DIGIT_LEN - 1) / NN_DIGIT_LEN + 1)
 /* Maximum digits */
 //#define MAX_NN_DIGIT 0xffffffff
 //#define MAX_NN_HALF_DIGIT 0xffff

 /* Macros.
  */
  //#define LOW_HALF(x) ((x) & MAX_NN_HALF_DIGIT)
  //#define HIGH_HALF(x) (((x) >> NN_HALF_DIGIT_BITS) & MAX_NN_HALF_DIGIT)
  //#define TO_HIGH_HALF(x) (((NN_DIGIT)(x)) << NN_HALF_DIGIT_BITS)
  //#define DIGIT_MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 1)) & 1)
  //#define DIGIT_2MSB(x) (unsigned int)(((x) >> (NN_DIGIT_BITS - 2)) & 3)
  //---------------------------------------------------------------------


  /*********************************************************************/

#define NN_ASSIGN_DIGIT(a, b, digits) {NN_AssignZero (a, digits); a[0] = b;}
#define NN_EQUAL(a, b, digits) (! NN_Cmp (a, b, digits))
#define NN_EVEN(a, digits) (((digits) == 0) || ! (a[0] & 1))


/*********************************************************************/

#define RANDOM_BYTES_NEEDED 256


/* ----------------------------------------------------------------- */

/*********************************************************************/

/***************************  MODULE *********************************/

/*********************************************************************/

SC_MODULE(dh_sw)
{
	sc_in<bool> hw_mult_done;
	sc_in<NN_DIGIT> in_data_low;
	sc_in<NN_DIGIT> in_data_high;
	sc_out<NN_DIGIT> out_data_1;
	sc_out<NN_DIGIT> out_data_2;
	sc_out<bool> hw_mult_enable;

	void process_sw();

	SC_CTOR(dh_sw)
	{
		SC_THREAD(process_sw);
		sensitive << hw_mult_done;
		//    dont_initialize();
	}

	/*********************************************************************/

	void R_memset(POINTER, int, unsigned int);
	void R_memcpy(POINTER, POINTER, unsigned int);

	/*********************************************************************/

	void MD5Init(MD5_CTX*);
	void MD5Update(MD5_CTX*, unsigned char*, unsigned int);
	void MD5Final(unsigned char[16], MD5_CTX*);

	void MD5Transform(UINT4[4], unsigned char[64]);
	void Encode(unsigned char*, UINT4*, unsigned int);
	void Decode(UINT4*, unsigned char*, unsigned int);
	void MD5_memcpy(POINTER, POINTER, unsigned int);
	void MD5_memset(POINTER, int, unsigned int);

	/*********************************************************************/

	/* CONVERSIONS
	   NN_Decode (a, digits, b, len)   Decodes character string b into a.
	   NN_Encode (a, len, b, digits)   Encodes a into character string b.

	   ASSIGNMENTS
	   NN_Assign (a, b, digits)        Assigns a = b.
	   NN_ASSIGN_DIGIT (a, b, digits)  Assigns a = b, where b is a digit.
	   NN_AssignZero (a, digits)    Assigns a = 0.
	   NN_Assign2Exp (a, b, digits)    Assigns a = 2^b.

	   ARITHMETIC OPERATIONS
	   NN_Add (a, b, c, digits)        Computes a = b + c.
	   NN_Sub (a, b, c, digits)        Computes a = b - c.
	   NN_Mult (a, b, c, digits)       Computes a = b * c.
	   NN_LShift (a, b, c, digits)     Computes a = b * 2^c.
	   NN_RShift (a, b, c, digits)     Computes a = b / 2^c.
	   NN_Div (a, b, c, cDigits, d, dDigits)  Computes a = c div d and b = c mod d.

	   NUMBER THEORY
	   NN_Mod (a, b, bDigits, c, cDigits)  Computes a = b mod c.
	   NN_ModMult (a, b, c, d, digits) Computes a = b * c mod d.
	   NN_ModExp (a, b, c, cDigits, d, dDigits)  Computes a = b^c mod d.
	   NN_ModInv (a, b, c, digits)     Computes a = 1/b mod c.
	   NN_Gcd (a, b, c, digits)        Computes a = gcd (b, c).

	   OTHER OPERATIONS
	   NN_EVEN (a, digits)             Returns 1 iff a is even.
	   NN_Cmp (a, b, digits)           Returns sign of a - b.
	   NN_EQUAL (a, digits)            Returns 1 iff a = b.
	   NN_Zero (a, digits)             Returns 1 iff a = 0.
	   NN_Digits (a, digits)           Returns significant length of a in digits.
	   NN_Bits (a, digits)             Returns significant length of a in bits.
	 */

	void NN_Decode(NN_DIGIT*, unsigned int, unsigned char*, unsigned int);
	void NN_Encode(unsigned char*, unsigned int, NN_DIGIT*, unsigned int);

	void NN_Assign(NN_DIGIT*, NN_DIGIT*, unsigned int);
	void NN_AssignZero(NN_DIGIT*, unsigned int);
	void NN_Assign2Exp(NN_DIGIT*, unsigned int, unsigned int);

	NN_DIGIT NN_Add(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int);
	NN_DIGIT NN_Sub(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int);
	void NN_Mult(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int);
	void NN_Div(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int, NN_DIGIT*, unsigned int);

	NN_DIGIT NN_LShift(NN_DIGIT*, NN_DIGIT*, unsigned int, unsigned int);
	NN_DIGIT NN_RShift(NN_DIGIT*, NN_DIGIT*, unsigned int, unsigned int);

	void NN_Mod(NN_DIGIT*, NN_DIGIT*, unsigned int, NN_DIGIT*, unsigned int);
	void NN_ModMult(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int);
	void NN_ModExp(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int, NN_DIGIT*, unsigned int);
	void NN_ModInv(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int);

	void NN_Gcd(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int);

	int NN_Cmp(NN_DIGIT*, NN_DIGIT*, unsigned int);
	int NN_Zero(NN_DIGIT*, unsigned int);

	unsigned int NN_Bits(NN_DIGIT*, unsigned int);
	unsigned int NN_Digits(NN_DIGIT*, unsigned int);
	unsigned int NN_DigitBits(NN_DIGIT);

	/*********************************************************************/

	void NN_DigitMult(NN_DIGIT[2], NN_DIGIT, NN_DIGIT);
	void NN_DigitDiv(NN_DIGIT*, NN_DIGIT[2], NN_DIGIT);

	NN_DIGIT NN_AddDigitMult(NN_DIGIT*, NN_DIGIT*, NN_DIGIT, NN_DIGIT*, unsigned int);
	NN_DIGIT NN_SubDigitMult(NN_DIGIT*, NN_DIGIT*, NN_DIGIT, NN_DIGIT*, unsigned int);

	/*********************************************************************/

	int GeneratePrime(NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, NN_DIGIT*, unsigned int, R_RANDOM_STRUCT*);

	int ProbablePrime(NN_DIGIT*, unsigned int);
	int SmallFactor(NN_DIGIT*, unsigned int);
	int FermatTest(NN_DIGIT*, unsigned int);

	/*********************************************************************/

	int R_GenerateBytes(unsigned char*, unsigned int, R_RANDOM_STRUCT*);
	int R_GenerateDHParams(R_DH_PARAMS*, unsigned int, unsigned int, R_RANDOM_STRUCT*);
	int R_SetupDHAgreement(unsigned char*, unsigned char*, unsigned int, R_DH_PARAMS*, R_RANDOM_STRUCT*);
	int R_ComputeDHAgreedKey(unsigned char*, unsigned char*, unsigned char*, unsigned int, R_DH_PARAMS*);

	/*********************************************************************/

	void PrintBigInteger(unsigned char*, unsigned int);
	void InitRandomStruct(R_RANDOM_STRUCT*);

	/*********************************************************************/


};

#endif /* end _DH_SW_H_ */