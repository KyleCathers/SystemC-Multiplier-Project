/* DHDEMO - demonstration program for Diffie-Hellman extensions to RSAREF
 */

 /* Copyright (C) 1993 RSA Laboratories, a division of
	RSA Data Security, Inc. All rights reserved.
  */

#include "systemc.h"
#include "dh_sw.h"


static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static unsigned char PRIME1[64] = {
  0xd0, 0x45, 0x1f, 0xfe, 0x2c, 0x64, 0xc4, 0xed, 0x6b, 0x0a, 0xe6,
  0x36, 0x5b, 0x7f, 0xef, 0x9c, 0x15, 0x42, 0x5e, 0x40, 0xa3, 0x7c,
  0xa5, 0xf8, 0x39, 0x86, 0x5e, 0x2c, 0xfb, 0x41, 0x69, 0xa0, 0xd8,
  0x25, 0xc9, 0x13, 0x0f, 0x88, 0x64, 0xff, 0xfc, 0xf3, 0xbf, 0xbe,
  0xb0, 0x27, 0x36, 0x60, 0x67, 0xaa, 0x27, 0xe2, 0x7b, 0xfc, 0xaf,
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static unsigned char GENERATOR1[64] = {
  0x0a, 0xcf, 0x95, 0x8c, 0x40, 0xd3, 0x01, 0xef, 0xc5, 0x15, 0x3e,
  0x7d, 0xcd, 0x5e, 0xf7, 0x5f, 0xec, 0x9e, 0x8f, 0xb0, 0xfa, 0xe6,
  0xa8, 0x0e, 0xe5, 0xc3, 0xb8, 0x4b, 0x9c, 0x0e, 0x51, 0x30, 0x51,
  0xb2, 0xb7, 0x54, 0x2e, 0x66, 0xb8, 0xd3, 0xa2, 0x5e, 0x93, 0x89,
  0x11, 0xad, 0x6b, 0xe5, 0xc2, 0x43, 0x95, 0x09, 0x9c, 0x6d, 0xda,
  0xa8, 0x6e, 0x18, 0x94, 0x2f, 0x29, 0x84, 0x27, 0x5a
};


/*************************************************************************/

void dh_sw::R_memset(
	POINTER output,                                             /* output block */
	int value,                                                         /* value */
	unsigned int len                                         /* length of block */
)
{
	if (len)
		memset(output, value, len);
}

void dh_sw::R_memcpy(
	POINTER output,                                             /* output block */
	POINTER input,                                               /* input block */
	unsigned int len                                        /* length of blocks */
)
{
	if (len)
		memcpy(output, input, len);
}


/*********************************************************************/

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void dh_sw::MD5Init(
	MD5_CTX* context                                         /* context */
)
{
	context->count[0] = context->count[1] = 0;

	/* Load magic initialization constants.
	 */
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
	 operation, processing another message block, and updating the
	 context.
 */
void dh_sw::MD5Update(
	MD5_CTX* context,                                        /* context */
	unsigned char* input,                                /* input block */
	unsigned int inputLen                      /* length of input block */
)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((UINT4)inputLen << 3))
		< ((UINT4)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.
	 */
	if (inputLen >= partLen) {
		MD5_memcpy
		((POINTER)& context->buffer[index], (POINTER)input, partLen);
		MD5Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD5Transform(context->state, &input[i]);

		index = 0;
	}
	else
		i = 0;

	/* Buffer remaining input */
	MD5_memcpy
	((POINTER)& context->buffer[index], (POINTER)& input[i],
		inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
	 the message digest and zeroizing the context.
 */
void dh_sw::MD5Final(
	unsigned char digest[16],                        /* message digest */
	MD5_CTX * context                                        /* context */
)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64.
	 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5Update(context, PADDING, padLen);

	/* Append length (before padding) */
	MD5Update(context, bits, 8);

	/* Store state in digest */
	Encode(digest, context->state, 16);

	/* Zeroize sensitive information.
	 */
	MD5_memset((POINTER)context, 0, sizeof(*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
void dh_sw::MD5Transform(
	UINT4 state[4],
	unsigned char block[64]
)
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode(x, block, 64);

	/* Round 1 */
	FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information.
	 */
	MD5_memset((POINTER)x, 0, sizeof(x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
	 a multiple of 4.
 */
void dh_sw::Encode(
	unsigned char* output,
	UINT4 * input,
	unsigned int len
)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
	 a multiple of 4.
 */
void dh_sw::Decode(
	UINT4 * output,
	unsigned char* input,
	unsigned int len
)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) |
		(((UINT4)input[j + 2]) << 16) | (((UINT4)input[j + 3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */
void dh_sw::MD5_memcpy(
	POINTER output,
	POINTER input,
	unsigned int len
)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
void dh_sw::MD5_memset(
	POINTER output,
	int value,
	unsigned int len
)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		((char*)output)[i] = (char)value;
}


/***********************************************************************/

int dh_sw::R_GenerateBytes(
	unsigned char* block,                                              /* block */
	unsigned int blockLen,                                   /* length of block */
	R_RANDOM_STRUCT * randomStruct                           /* random structure */
)
{
	MD5_CTX context;
	unsigned int available, i;

	if (randomStruct->bytesNeeded)
		return (RE_NEED_RANDOM);

	available = randomStruct->outputAvailable;

	while (blockLen > available) {
		R_memcpy
		((POINTER)block, (POINTER)& randomStruct->output[16 - available],
			available);
		block += available;
		blockLen -= available;

		/* generate new output */
		MD5Init(&context);
		MD5Update(&context, randomStruct->state, 16);
		MD5Final(randomStruct->output, &context);
		available = 16;

		/* increment state */
		for (i = 0; i < 16; i++)
			if (randomStruct->state[15 - i]++)
				break;
	}

	R_memcpy
	((POINTER)block, (POINTER)& randomStruct->output[16 - available], blockLen);
	randomStruct->outputAvailable = available - blockLen;

	return (0);
}


/*********************************************************************/

/* Computes a = b * c, where b and c are digits.

   Lengths: a[2].
 */
void dh_sw::NN_DigitMult(NN_DIGIT a[2], NN_DIGIT b, NN_DIGIT c)
{
	out_data_1.write(b);
	out_data_2.write(c);
	hw_mult_enable.write(true);

	// wait for HW multiplier to finish
	do {
		wait();
	} while (hw_mult_done.read() == false);

	// read results from HW multiplier
	a[0] = in_data_low.read();
	a[1] = in_data_high.read();

	// deassert HW multiplier enable
	hw_mult_enable.write(false);
	wait();
}

/* Sets a = b / c, where a and c are digits.

   Lengths: b[2].
   Assumes b[1] < c and HIGH_HALF (c) > 0. For efficiency, c should be
   normalized.
 */
void dh_sw::NN_DigitDiv(NN_DIGIT * a, NN_DIGIT b[2], NN_DIGIT c)
{
	NN_DIGIT t[2], u, v;
	NN_HALF_DIGIT aHigh, aLow, cHigh, cLow;

	cHigh = (NN_HALF_DIGIT)HIGH_HALF(c);
	cLow = (NN_HALF_DIGIT)LOW_HALF(c);

	t[0] = b[0];
	t[1] = b[1];


	/* Underestimate high half of quotient and subtract. */
	if (cHigh == MAX_NN_HALF_DIGIT)
		aHigh = (NN_HALF_DIGIT)HIGH_HALF(t[1]);
	else
		aHigh = (NN_HALF_DIGIT)(t[1] / (cHigh + 1));

	u = (NN_DIGIT)aHigh * (NN_DIGIT)cLow;
	v = (NN_DIGIT)aHigh * (NN_DIGIT)cHigh;
	if ((t[0] -= TO_HIGH_HALF(u)) > (MAX_NN_DIGIT - TO_HIGH_HALF(u)))
		t[1]--;
	t[1] -= HIGH_HALF(u);
	t[1] -= v;

	/* Correct estimate. */
	while ((t[1] > cHigh) || ((t[1] == cHigh) && (t[0] >= TO_HIGH_HALF(cLow)))) {
		if ((t[0] -= TO_HIGH_HALF(cLow)) > MAX_NN_DIGIT - TO_HIGH_HALF(cLow))
			t[1]--;
		t[1] -= cHigh;
		aHigh++;
	}

	/* Underestimate low half of quotient and subtract. */
	if (cHigh == MAX_NN_HALF_DIGIT)
		aLow = (NN_HALF_DIGIT)LOW_HALF(t[1]);
	else
		aLow = (NN_HALF_DIGIT)((TO_HIGH_HALF(t[1]) + HIGH_HALF(t[0])) / (cHigh + 1));

	u = (NN_DIGIT)aLow * (NN_DIGIT)cLow;
	v = (NN_DIGIT)aLow * (NN_DIGIT)cHigh;
	if ((t[0] -= u) > (MAX_NN_DIGIT - u))
		t[1]--;
	if ((t[0] -= TO_HIGH_HALF(v)) > (MAX_NN_DIGIT - TO_HIGH_HALF(v)))
		t[1]--;
	t[1] -= HIGH_HALF(v);

	/* Correct estimate. */
	while ((t[1] > 0) || ((t[1] == 0) && t[0] >= c)) {
		if ((t[0] -= c) > (MAX_NN_DIGIT - c))
			t[1]--;
		aLow++;
	}

	*a = TO_HIGH_HALF(aHigh) + aLow;
}


/*********************************************************************/

/* Decodes character string b into a, where character string is ordered
   from most to least significant.

   Lengths: a[digits], b[len].
   Assumes b[i] = 0 for i < len - digits * NN_DIGIT_LEN. (Otherwise most
   significant bytes are truncated.)
 */
void dh_sw::NN_Decode(
	NN_DIGIT * a,
	unsigned int digits,
	unsigned char* b,
	unsigned int len
)
{
	NN_DIGIT t;
	int j;
	unsigned int i, u;

	for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
		t = 0;
		for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
			t |= ((NN_DIGIT)b[j]) << u;
		a[i] = t;
	}

	for (; i < digits; i++)
		a[i] = 0;
}

/* Encodes b into character string a, where character string is ordered
   from most to least significant.

   Lengths: a[len], b[digits].
   Assumes NN_Bits (b, digits) <= 8 * len. (Otherwise most significant
   digits are truncated.)
 */
void dh_sw::NN_Encode(
	unsigned char* a,
	unsigned int len,
	NN_DIGIT * b,
	unsigned int digits
)
{
	NN_DIGIT t;
	int j;
	unsigned int i, u;

	for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
		t = b[i];
		for (u = 0; j >= 0 && u < NN_DIGIT_BITS; j--, u += 8)
			a[j] = (unsigned char)(t >> u);
	}

	for (; j >= 0; j--)
		a[j] = 0;
}

/* Assigns a = b.

   Lengths: a[digits], b[digits].
 */
void dh_sw::NN_Assign(
	NN_DIGIT * a,
	NN_DIGIT * b,
	unsigned int digits
)
{
	unsigned int i;

	for (i = 0; i < digits; i++)
		a[i] = b[i];
}

/* Assigns a = 0.

   Lengths: a[digits].
 */
void dh_sw::NN_AssignZero(
	NN_DIGIT * a,
	unsigned int digits
)
{
	unsigned int i;

	for (i = 0; i < digits; i++)
		a[i] = 0;
}

/* Assigns a = 2^b.

   Lengths: a[digits].
   Requires b < digits * NN_DIGIT_BITS.
 */
void dh_sw::NN_Assign2Exp(
	NN_DIGIT * a,
	unsigned int b,
	unsigned int digits
)
{
	NN_AssignZero(a, digits);

	if (b >= digits * NN_DIGIT_BITS)
		return;

	a[b / NN_DIGIT_BITS] = (NN_DIGIT)1 << (b % NN_DIGIT_BITS);
}

/* Computes a = b + c. Returns carry.

   Lengths: a[digits], b[digits], c[digits].
 */
NN_DIGIT dh_sw::NN_Add(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	unsigned int digits
)
{
	NN_DIGIT ai, carry;
	unsigned int i;

	carry = 0;

	for (i = 0; i < digits; i++) {
		if ((ai = b[i] + carry) < carry)
			ai = c[i];
		else if ((ai += c[i]) < c[i])
			carry = 1;
		else
			carry = 0;
		a[i] = ai;
	}

	return (carry);
}

/* Computes a = b - c. Returns borrow.

   Lengths: a[digits], b[digits], c[digits].
 */
NN_DIGIT dh_sw::NN_Sub(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	unsigned int digits
)
{
	NN_DIGIT ai, borrow;
	unsigned int i;

	borrow = 0;

	for (i = 0; i < digits; i++) {
		if ((ai = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
			ai = MAX_NN_DIGIT - c[i];
		else if ((ai -= c[i]) > (MAX_NN_DIGIT - c[i]))
			borrow = 1;
		else
			borrow = 0;
		a[i] = ai;
	}

	return (borrow);
}

/* Computes a = b * c.

   Lengths: a[2*digits], b[digits], c[digits].
   Assumes digits < MAX_NN_DIGITS.
 */
void dh_sw::NN_Mult(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	unsigned int digits
)
{
	NN_DIGIT t[2 * MAX_NN_DIGITS];
	unsigned int bDigits, cDigits, i;

	NN_AssignZero(t, 2 * digits);

	bDigits = NN_Digits(b, digits);
	cDigits = NN_Digits(c, digits);

	for (i = 0; i < bDigits; i++)
		t[i + cDigits] += NN_AddDigitMult(&t[i], &t[i], b[i], c, cDigits);

	NN_Assign(a, t, 2 * digits);

	/* Zeroize potentially sensitive information.
	 */
	R_memset((POINTER)t, 0, sizeof(t));
}

/* Computes a = b * 2^c (i.e., shifts left c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires c < NN_DIGIT_BITS.
 */
NN_DIGIT dh_sw::NN_LShift(
	NN_DIGIT * a,
	NN_DIGIT * b,
	unsigned int c,
	unsigned int digits
)
{
	NN_DIGIT bi, carry;
	unsigned int i, t;

	if (c >= NN_DIGIT_BITS)
		return (0);

	t = NN_DIGIT_BITS - c;

	carry = 0;

	for (i = 0; i < digits; i++) {
		bi = b[i];
		a[i] = (bi << c) | carry;
		carry = c ? (bi >> t) : 0;
	}

	return (carry);
}

/* Computes a = c div 2^c (i.e., shifts right c bits), returning carry.

   Lengths: a[digits], b[digits].
   Requires: c < NN_DIGIT_BITS.
 */
NN_DIGIT dh_sw::NN_RShift(
	NN_DIGIT * a,
	NN_DIGIT * b,
	unsigned int c,
	unsigned int digits
)
{
	NN_DIGIT bi, carry;
	int i;
	unsigned int t;

	if (c >= NN_DIGIT_BITS)
		return (0);

	t = NN_DIGIT_BITS - c;

	carry = 0;

	for (i = digits - 1; i >= 0; i--) {
		bi = b[i];
		a[i] = (bi >> c) | carry;
		carry = c ? (bi << t) : 0;
	}

	return (carry);
}

/* Computes a = c div d and b = c mod d.

   Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes d > 0, cDigits < 2 * MAX_NN_DIGITS,
		   dDigits < MAX_NN_DIGITS.
 */
void dh_sw::NN_Div(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	unsigned int cDigits,
	NN_DIGIT * d,
	unsigned int dDigits
)
{
	NN_DIGIT ai, cc[2 * MAX_NN_DIGITS + 1], dd[MAX_NN_DIGITS], t;
	int i;
	unsigned int ddDigits, shift;

	ddDigits = NN_Digits(d, dDigits);
	if (ddDigits == 0)
		return;

	/* Normalize operands.
	 */
	shift = NN_DIGIT_BITS - NN_DigitBits(d[ddDigits - 1]);
	NN_AssignZero(cc, ddDigits);
	cc[cDigits] = NN_LShift(cc, c, shift, cDigits);
	NN_LShift(dd, d, shift, ddDigits);
	t = dd[ddDigits - 1];

	NN_AssignZero(a, cDigits);

	for (i = cDigits - ddDigits; i >= 0; i--) {
		/* Underestimate quotient digit and subtract.
		 */
		if (t == MAX_NN_DIGIT)
			ai = cc[i + ddDigits];
		else
			NN_DigitDiv(&ai, &cc[i + ddDigits - 1], t + 1);
		cc[i + ddDigits] -= NN_SubDigitMult(&cc[i], &cc[i], ai, dd, ddDigits);

		/* Correct estimate.
		 */
		while (cc[i + ddDigits] || (NN_Cmp(&cc[i], dd, ddDigits) >= 0)) {
			ai++;
			cc[i + ddDigits] -= NN_Sub(&cc[i], &cc[i], dd, ddDigits);
		}

		a[i] = ai;
	}

	/* Restore result.
	 */
	NN_AssignZero(b, dDigits);
	NN_RShift(b, cc, shift, ddDigits);

	/* Zeroize potentially sensitive information.
	 */
	R_memset((POINTER)cc, 0, sizeof(cc));
	R_memset((POINTER)dd, 0, sizeof(dd));
}

/* Computes a = b mod c.

   Lengths: a[cDigits], b[bDigits], c[cDigits].
   Assumes c > 0, bDigits < 2 * MAX_NN_DIGITS, cDigits < MAX_NN_DIGITS.
 */
void dh_sw::NN_Mod(
	NN_DIGIT * a,
	NN_DIGIT * b,
	unsigned int bDigits,
	NN_DIGIT * c,
	unsigned int cDigits
)
{
	NN_DIGIT t[2 * MAX_NN_DIGITS];

	NN_Div(t, a, b, bDigits, c, cDigits);

	/* Zeroize potentially sensitive information.
	 */
	R_memset((POINTER)t, 0, sizeof(t));
}

/* Computes a = b * c mod d.

   Lengths: a[digits], b[digits], c[digits], d[digits].
   Assumes d > 0, digits < MAX_NN_DIGITS.
 */
void dh_sw::NN_ModMult(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	NN_DIGIT * d,
	unsigned int digits
)
{
	NN_DIGIT t[2 * MAX_NN_DIGITS];

	NN_Mult(t, b, c, digits);
	NN_Mod(a, t, 2 * digits, d, digits);

	/* Zeroize potentially sensitive information.
	 */
	R_memset((POINTER)t, 0, sizeof(t));
}

/* Computes a = b^c mod d.

   Lengths: a[dDigits], b[dDigits], c[cDigits], d[dDigits].
   Assumes d > 0, cDigits > 0, dDigits < MAX_NN_DIGITS.
 */
void dh_sw::NN_ModExp(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	unsigned int cDigits,
	NN_DIGIT * d,
	unsigned int dDigits
)
{
	NN_DIGIT bPower[3][MAX_NN_DIGITS], ci, t[MAX_NN_DIGITS];
	int i;
	unsigned int ciBits, j, s;

	/* Store b, b^2 mod d, and b^3 mod d.
	 */
	NN_Assign(bPower[0], b, dDigits);
	NN_ModMult(bPower[1], bPower[0], b, d, dDigits);
	NN_ModMult(bPower[2], bPower[1], b, d, dDigits);

	NN_ASSIGN_DIGIT(t, 1, dDigits);

	cDigits = NN_Digits(c, cDigits);
	for (i = cDigits - 1; i >= 0; i--) {
		ci = c[i];
		ciBits = NN_DIGIT_BITS;

		/* Scan past leading zero bits of most significant digit.
		 */
		if (i == (int)(cDigits - 1)) {
			while (!DIGIT_2MSB(ci)) {
				ci <<= 2;
				ciBits -= 2;
			}
		}

		for (j = 0; j < ciBits; j += 2, ci <<= 2) {
			/* Compute t = t^4 * b^s mod d, where s = two MSB's of ci.
			 */
			NN_ModMult(t, t, t, d, dDigits);
			NN_ModMult(t, t, t, d, dDigits);
			if ((s = DIGIT_2MSB(ci)) != 0)
				NN_ModMult(t, t, bPower[s - 1], d, dDigits);
		}
	}

	NN_Assign(a, t, dDigits);

	/* Zeroize potentially sensitive information.
	 */
	R_memset((POINTER)bPower, 0, sizeof(bPower));
	R_memset((POINTER)t, 0, sizeof(t));
}

/* Compute a = 1/b mod c, assuming inverse exists.

   Lengths: a[digits], b[digits], c[digits].
   Assumes gcd (b, c) = 1, digits < MAX_NN_DIGITS.
 */
void dh_sw::NN_ModInv(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	unsigned int digits
)
{
	NN_DIGIT q[MAX_NN_DIGITS], t1[MAX_NN_DIGITS], t3[MAX_NN_DIGITS],
		u1[MAX_NN_DIGITS], u3[MAX_NN_DIGITS], v1[MAX_NN_DIGITS],
		v3[MAX_NN_DIGITS], w[2 * MAX_NN_DIGITS];
	int u1Sign;

	/* Apply extended Euclidean algorithm, modified to avoid negative
	   numbers.
	 */
	NN_ASSIGN_DIGIT(u1, 1, digits);
	NN_AssignZero(v1, digits);
	NN_Assign(u3, b, digits);
	NN_Assign(v3, c, digits);
	u1Sign = 1;

	while (!NN_Zero(v3, digits)) {
		NN_Div(q, t3, u3, digits, v3, digits);
		NN_Mult(w, q, v1, digits);
		NN_Add(t1, u1, w, digits);
		NN_Assign(u1, v1, digits);
		NN_Assign(v1, t1, digits);
		NN_Assign(u3, v3, digits);
		NN_Assign(v3, t3, digits);
		u1Sign = -u1Sign;
	}

	/* Negate result if sign is negative.
	  */
	if (u1Sign < 0)
		NN_Sub(a, c, u1, digits);
	else
		NN_Assign(a, u1, digits);

	/* Zeroize potentially sensitive information.
	 */
	R_memset((POINTER)q, 0, sizeof(q));
	R_memset((POINTER)t1, 0, sizeof(t1));
	R_memset((POINTER)t3, 0, sizeof(t3));
	R_memset((POINTER)u1, 0, sizeof(u1));
	R_memset((POINTER)u3, 0, sizeof(u3));
	R_memset((POINTER)v1, 0, sizeof(v1));
	R_memset((POINTER)v3, 0, sizeof(v3));
	R_memset((POINTER)w, 0, sizeof(w));
}

/* Computes a = gcd(b, c).

   Lengths: a[digits], b[digits], c[digits].
   Assumes b > c, digits < MAX_NN_DIGITS.
 */
void dh_sw::NN_Gcd(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	unsigned int digits
)
{
	NN_DIGIT t[MAX_NN_DIGITS], u[MAX_NN_DIGITS], v[MAX_NN_DIGITS];

	NN_Assign(u, b, digits);
	NN_Assign(v, c, digits);

	while (!NN_Zero(v, digits)) {
		NN_Mod(t, u, digits, v, digits);
		NN_Assign(u, v, digits);
		NN_Assign(v, t, digits);
	}

	NN_Assign(a, u, digits);

	/* Zeroize potentially sensitive information.
	 */
	R_memset((POINTER)t, 0, sizeof(t));
	R_memset((POINTER)u, 0, sizeof(u));
	R_memset((POINTER)v, 0, sizeof(v));
}

/* Returns sign of a - b.

   Lengths: a[digits], b[digits].
 */
int dh_sw::NN_Cmp(
	NN_DIGIT * a,
	NN_DIGIT * b,
	unsigned int digits
)
{
	int i;

	for (i = digits - 1; i >= 0; i--) {
		if (a[i] > b[i])
			return (1);
		if (a[i] < b[i])
			return (-1);
	}

	return (0);
}

/* Returns nonzero iff a is zero.

   Lengths: a[digits].
 */
int dh_sw::NN_Zero(
	NN_DIGIT * a,
	unsigned int digits
)
{
	unsigned int i;

	for (i = 0; i < digits; i++)
		if (a[i])
			return (0);

	return (1);
}

/* Returns the significant length of a in bits.

   Lengths: a[digits].
 */
unsigned int dh_sw::NN_Bits(
	NN_DIGIT * a,
	unsigned int digits
)
{
	if ((digits = NN_Digits(a, digits)) == 0)
		return (0);

	return ((digits - 1) * NN_DIGIT_BITS + NN_DigitBits(a[digits - 1]));
}

/* Returns the significant length of a in digits.

   Lengths: a[digits].
 */
unsigned int dh_sw::NN_Digits(
	NN_DIGIT * a,
	unsigned int digits
)
{
	int i;

	for (i = digits - 1; i >= 0; i--)
		if (a[i])
			break;

	return (i + 1);
}

/* Computes a = b + c*d, where c is a digit. Returns carry.

   Lengths: a[digits], b[digits], d[digits].
 */
NN_DIGIT dh_sw::NN_AddDigitMult(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT c,
	NN_DIGIT * d,
	unsigned int digits
)
{
	NN_DIGIT carry, t[2];
	unsigned int i;

	if (c == 0)
		return (0);

	carry = 0;
	for (i = 0; i < digits; i++) {
		NN_DigitMult(t, c, d[i]);
		if ((a[i] = b[i] + carry) < carry)
			carry = 1;
		else
			carry = 0;
		if ((a[i] += t[0]) < t[0])
			carry++;
		carry += t[1];
	}

	return (carry);
}

/* Computes a = b - c*d, where c is a digit. Returns borrow.

   Lengths: a[digits], b[digits], d[digits].
 */
NN_DIGIT dh_sw::NN_SubDigitMult(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT c,
	NN_DIGIT * d,
	unsigned int digits
)
{
	NN_DIGIT borrow, t[2];
	unsigned int i;

	if (c == 0)
		return (0);

	borrow = 0;
	for (i = 0; i < digits; i++) {
		NN_DigitMult(t, c, d[i]);
		if ((a[i] = b[i] - borrow) > (MAX_NN_DIGIT - borrow))
			borrow = 1;
		else
			borrow = 0;
		if ((a[i] -= t[0]) > (MAX_NN_DIGIT - t[0]))
			borrow++;
		borrow += t[1];
	}

	return (borrow);
}

/* Returns the significant length of a in bits, where a is a digit.
 */
unsigned int dh_sw::NN_DigitBits(
	NN_DIGIT a
)
{
	unsigned int i;

	for (i = 0; i < NN_DIGIT_BITS; i++, a >>= 1)
		if (a == 0)
			break;

	return (i);
}



/****************************************************************************/

/* Generates a probable prime a between b and c such that a-1 is
   divisible by d.

   Lengths: a[digits], b[digits], c[digits], d[digits].
   Assumes b < c, digits < MAX_NN_DIGITS.

   Returns RE_NEED_RANDOM if randomStruct not seeded, RE_DATA if
   unsuccessful.
 */
int dh_sw::GeneratePrime(
	NN_DIGIT * a,
	NN_DIGIT * b,
	NN_DIGIT * c,
	NN_DIGIT * d,
	unsigned int digits,
	R_RANDOM_STRUCT * randomStruct
)
{
	int status;
	unsigned char block[MAX_NN_DIGITS * NN_DIGIT_LEN];
	NN_DIGIT t[MAX_NN_DIGITS], u[MAX_NN_DIGITS];

	/* Generate random number between b and c.
	 */
	if ((status = R_GenerateBytes(block, digits * NN_DIGIT_LEN, randomStruct)))
		return (status);
	NN_Decode(a, digits, block, digits * NN_DIGIT_LEN);
	NN_Sub(t, c, b, digits);
	NN_ASSIGN_DIGIT(u, 1, digits);
	NN_Add(t, t, u, digits);
	NN_Mod(a, a, digits, t, digits);
	NN_Add(a, a, b, digits);

	/* Adjust so that a-1 is divisible by d.
	 */
	NN_Mod(t, a, digits, d, digits);
	NN_Sub(a, a, t, digits);
	NN_Add(a, a, u, digits);
	if (NN_Cmp(a, b, digits) < 0)
		NN_Add(a, a, d, digits);
	if (NN_Cmp(a, c, digits) > 0)
		NN_Sub(a, a, d, digits);

	/* Search to c in steps of d.
	 */
	NN_Assign(t, c, digits);
	NN_Sub(t, t, d, digits);

	while (!ProbablePrime(a, digits)) {
		if (NN_Cmp(a, t, digits) > 0)
			return (RE_DATA);
		NN_Add(a, a, d, digits);
	}

	return (0);
}

/* Returns nonzero iff a is a probable prime.

   Lengths: a[aDigits].
   Assumes aDigits < MAX_NN_DIGITS.
 */
int dh_sw::ProbablePrime(
	NN_DIGIT * a,
	unsigned int aDigits
)
{
	return (!SmallFactor(a, aDigits) && FermatTest(a, aDigits));
}

/* Returns nonzero iff a has a prime factor in SMALL_PRIMES.

   Lengths: a[aDigits].
   Assumes aDigits < MAX_NN_DIGITS.
 */
int dh_sw::SmallFactor(
	NN_DIGIT * a,
	unsigned int aDigits
)
{
	int status;
	NN_DIGIT t[1];
	unsigned int i;

	unsigned int SMALL_PRIMES[4] = { 3, 5, 7, 11 };

	status = 0;

	for (i = 0; i < 4; i++) {
		NN_ASSIGN_DIGIT(t, SMALL_PRIMES[i], 1);
		if ((aDigits == 1) && !NN_Cmp(a, t, 1))
			break;
		NN_Mod(t, a, aDigits, t, 1);
		if (NN_Zero(t, 1)) {
			status = 1;
			break;
		}
	}

	/* Zeroize sensitive information.
	 */
	i = 0;
	R_memset((POINTER)t, 0, sizeof(t));

	return (status);
}

/* Returns nonzero iff a passes Fermat's test for witness 2.
   (All primes pass the test, and nearly all composites fail.)

   Lengths: a[aDigits].
   Assumes aDigits < MAX_NN_DIGITS.
 */
int dh_sw::FermatTest(
	NN_DIGIT * a,
	unsigned int aDigits
)
{
	int status;
	NN_DIGIT t[MAX_NN_DIGITS], u[MAX_NN_DIGITS];

	NN_ASSIGN_DIGIT(t, 2, aDigits);
	NN_ModExp(u, t, a, aDigits, a, aDigits);

	status = NN_EQUAL(t, u, aDigits);

	/* Zeroize sensitive information.
	 */
	R_memset((POINTER)u, 0, sizeof(u));

	return (status);
}


/****************************************************************************/


/* Generates Diffie-Hellman parameters.
 */
int dh_sw::R_GenerateDHParams(
	R_DH_PARAMS * params,                       /* new Diffie-Hellman parameters */
	unsigned int primeBits,                          /* length of prime in bits */
	unsigned int subPrimeBits,                    /* length of subprime in bits */
	R_RANDOM_STRUCT * randomStruct                           /* random structure */
)
{
	int status;
	NN_DIGIT g[MAX_NN_DIGITS], p[MAX_NN_DIGITS], q[MAX_NN_DIGITS],
		t[MAX_NN_DIGITS], u[MAX_NN_DIGITS], v[MAX_NN_DIGITS];
	unsigned int pDigits;

	pDigits = (primeBits + NN_DIGIT_BITS - 1) / NN_DIGIT_BITS;

	/* Generate subprime q between 2^(subPrimeBits-1) and
		 2^subPrimeBits-1, searching in steps of 2.
	 */
	NN_Assign2Exp(t, subPrimeBits - 1, pDigits);
	NN_Assign(u, t, pDigits);
	NN_ASSIGN_DIGIT(v, 1, pDigits);
	NN_Sub(v, t, v, pDigits);
	NN_Add(u, u, v, pDigits);
	NN_ASSIGN_DIGIT(v, 2, pDigits);
	if ((status = GeneratePrime(q, t, u, v, pDigits, randomStruct)))
		return (status);

	/* Generate prime p between 2^(primeBits-1) and 2^primeBits-1,
		 searching in steps of 2*q.
	 */
	NN_Assign2Exp(t, primeBits - 1, pDigits);
	NN_Assign(u, t, pDigits);
	NN_ASSIGN_DIGIT(v, 1, pDigits);
	NN_Sub(v, t, v, pDigits);
	NN_Add(u, u, v, pDigits);
	NN_LShift(v, q, 1, pDigits);
	if ((status = GeneratePrime(p, t, u, v, pDigits, randomStruct)))
		return (status);

	/* Generate generator g for subgroup as 2^((p-1)/q) mod p.
	 */
	NN_ASSIGN_DIGIT(g, 2, pDigits);
	NN_Div(t, u, p, pDigits, q, pDigits);
	NN_ModExp(g, g, t, pDigits, p, pDigits);

	params->generatorLen = params->primeLen = DH_PRIME_LEN(primeBits);
	NN_Encode(params->prime, params->primeLen, p, pDigits);
	NN_Encode(params->generator, params->generatorLen, g, pDigits);

	return (0);
}

/* Sets up Diffie-Hellman key agreement. Public value has same length
   as prime.
 */
int dh_sw::R_SetupDHAgreement(
	unsigned char* publicValue,                             /* new public value */
	unsigned char* privateValue,                           /* new private value */
	unsigned int privateValueLen,                    /* length of private value */
	R_DH_PARAMS * params,                           /* Diffie-Hellman parameters */
	R_RANDOM_STRUCT * randomStruct                           /* random structure */
)
{
	int status;
	NN_DIGIT g[MAX_NN_DIGITS], p[MAX_NN_DIGITS], x[MAX_NN_DIGITS],
		y[MAX_NN_DIGITS];
	unsigned int pDigits, xDigits;

	NN_Decode(p, MAX_NN_DIGITS, params->prime, params->primeLen);
	pDigits = NN_Digits(p, MAX_NN_DIGITS);
	NN_Decode(g, pDigits, params->generator, params->generatorLen);

	/* Generate private value.
	 */
	if ((status = R_GenerateBytes(privateValue, privateValueLen, randomStruct)))
		return (status);
	NN_Decode(x, pDigits, privateValue, privateValueLen);
	xDigits = NN_Digits(x, pDigits);

	/* Compute y = g^x mod p.
	 */
	NN_ModExp(y, g, x, xDigits, p, pDigits);

	NN_Encode(publicValue, params->primeLen, y, pDigits);

	/* Zeroize sensitive information.
	 */
	R_memset((POINTER)x, 0, sizeof(x));

	return (0);
}

/* Computes agreed key from the other party's public value, a private
   value, and Diffie-Hellman parameters. Other public value and
   agreed-upon key have same length as prime.

   Requires otherPublicValue < prime.
 */
int dh_sw::R_ComputeDHAgreedKey(
	unsigned char* agreedKey,                                 /* new agreed key */
	unsigned char* otherPublicValue,                    /* other's public value */
	unsigned char* privateValue,                               /* private value */
	unsigned int privateValueLen,                    /* length of private value */
	R_DH_PARAMS * params                            /* Diffie-Hellman parameters */
)
{
	NN_DIGIT p[MAX_NN_DIGITS], x[MAX_NN_DIGITS], y[MAX_NN_DIGITS],
		z[MAX_NN_DIGITS];
	unsigned int pDigits, xDigits;

	NN_Decode(p, MAX_NN_DIGITS, params->prime, params->primeLen);
	pDigits = NN_Digits(p, MAX_NN_DIGITS);
	NN_Decode(x, pDigits, privateValue, privateValueLen);
	xDigits = NN_Digits(x, pDigits);
	NN_Decode(y, pDigits, otherPublicValue, params->primeLen);

	if (NN_Cmp(y, p, pDigits) >= 0)
		return (RE_DATA);

	/* Compute z = y^x mod p.
	 */
	NN_ModExp(z, y, x, xDigits, p, pDigits);

	NN_Encode(agreedKey, params->primeLen, z, pDigits);

	/* Zeroize sensitive information.
	 */
	R_memset((POINTER)x, 0, sizeof(x));
	R_memset((POINTER)z, 0, sizeof(z));

	return (0);
}


/*****************************************************************************/

void dh_sw::PrintBigInteger(
	unsigned char* integer2,
	unsigned int integerLen2
)
{
	while (*integer2 == 0 && integerLen2 > 0) {
		integer2++;
		integerLen2--;
	}

	if (integerLen2 == 0) {
		printf("00\n");
		return;
	}

	for (; integerLen2 > 0; integerLen2--)
		printf("%02x ", (unsigned int)(*integer2++));

	printf("\n");
}


/* Initialize the random structure with all zero seed bytes for test purposes.
   NOTE that this will cause the output of the "random" process to be
	 the same every time.  To produce random bytes, the random struct
	 needs random seeds!
 */
void dh_sw::InitRandomStruct(
	R_RANDOM_STRUCT * randomStruct
)
{
	static unsigned char seedByte[1] = { 0 };

	MD5_CTX context;
	unsigned char digest[16];
	unsigned int i, x;

	randomStruct->bytesNeeded = RANDOM_BYTES_NEEDED;
	R_memset((POINTER)randomStruct->state, 0, sizeof(randomStruct->state));
	randomStruct->outputAvailable = 0;


	/* Initialize with all zero seed bytes, which will not yield an actual
		 random number output.
	 */
	while (1) {
		if (randomStruct->bytesNeeded == 0)
			break;

		MD5Init(&context);
		MD5Update(&context, seedByte, 1);
		MD5Final(digest, &context);

		/* add digest to state */
		x = 0;
		for (i = 0; i < 16; i++) {
			x += randomStruct->state[15 - i] + digest[15 - i];
			randomStruct->state[15 - i] = (unsigned char)x;
			x >>= 8;
		}

		if (randomStruct->bytesNeeded < 1)
			randomStruct->bytesNeeded = 0;
		else
			randomStruct->bytesNeeded -= 1;

		/* Zeroize sensitive information.
		 */
		R_memset((POINTER)digest, 0, sizeof(digest));
		x = 0;

	}
}


/* ---------------------------------------------------------------------- */

/*********************************************************************/

/***********************  MAIN PROCESS *******************************/

/*********************************************************************/

void dh_sw::process_sw()
{

	R_DH_PARAMS PARAMS1, PARAMS2;

	unsigned char PRIME2[DH_PRIME_LEN(KEY_LENGTH)];
	unsigned char GENERATOR2[DH_PRIME_LEN(KEY_LENGTH)];

	unsigned char gen_privateValue[KEY_LENGTH];
	unsigned char gen_publicValue[sizeof(PRIME1)];
	unsigned char gen_otherPublicValue[sizeof(PRIME1)];

	unsigned char AGREED_KEY1[sizeof(PRIME1)];
	unsigned char AGREED_KEY2[DH_PRIME_LEN(KEY_LENGTH)];


	// Original main() program...

	R_RANDOM_STRUCT randomStruct;
	R_RANDOM_STRUCT randomStruct2;
	R_DH_PARAMS* params;

	int status, keys_exchanged;
	unsigned char* agreedKey;
	unsigned char privateValue[KEY_LENGTH];
	unsigned char publicValue[sizeof(PRIME1)];


	PARAMS1.prime = PRIME1;
	PARAMS1.primeLen = sizeof(PRIME1);
	PARAMS1.generator = GENERATOR1;
	PARAMS1.generatorLen = sizeof(GENERATOR1);

	PARAMS2.prime = PRIME2;
	PARAMS2.generator = GENERATOR2;


	/* We first generate parameters, and then do some key exchange each followed by a key computation...*/
	keys_exchanged = 0;


	/* Initialize first random structure */

	InitRandomStruct(&randomStruct);

	/* Generate parameters */
	if ((status = R_GenerateDHParams
	(&PARAMS2, KEY_LENGTH, (KEY_LENGTH / 2), &randomStruct))) {
		printf("ERROR: Code 0x%04x while generating parameters\n", status);
		//return(0);
		sc_stop();
	}

	/* Set up agreement */

	{
		params = &PARAMS1;

		/* Set up a break point with a do {} while (0) so that we can
			zeroize the sensitive buffers before exiting.
		*/
		do {
			if ((status = R_SetupDHAgreement
			(publicValue, privateValue, KEY_LENGTH, params, &randomStruct))) {
				printf("ERROR: Code 0x%04x while setting up key agreement\n", status);
				break;
			}

			memcpy(gen_otherPublicValue, publicValue, params->primeLen);

		} while (0);

		memset((POINTER)privateValue, 0, KEY_LENGTH);
	}


	/*** Exchange keys ***/

	while (keys_exchanged != NUM_KEYEXCHANGE)
	{
		keys_exchanged++;

		/* Initialize second random structure */

		InitRandomStruct(&randomStruct2);


		/*** Generate parameters ***/

		if ((status = R_GenerateDHParams
		(&PARAMS2, KEY_LENGTH, (KEY_LENGTH / 2), &randomStruct2))) {
			printf("ERROR: Code 0x%04x while generating parameters\n", status);
			break;
		}


		/*** Setup agreement ***/

		{
			params = &PARAMS1;

			/* Set up a break point with a do {} while (0) so that we can
				zeroize the sensitive buffers before exiting.
			*/
			do {
				if ((status = R_SetupDHAgreement
				(publicValue, privateValue, KEY_LENGTH, params, &randomStruct2))) {
					printf("ERROR: Code 0x%04x while setting up key agreement\n", status);
					break;
				}

				if (gen_privateValue != NULL)
					strncpy((char*)gen_privateValue, (char*)privateValue, KEY_LENGTH);

				memcpy(gen_publicValue, publicValue, params->primeLen);

			} while (0);

			memset((POINTER)privateValue, 0, KEY_LENGTH);
		}


		/*** Compute agreed key ***/

		{
			if ((keys_exchanged % 2) == 0) {
				params = &PARAMS1;
				agreedKey = AGREED_KEY1;
			}
			else {
				params = &PARAMS2;
				agreedKey = AGREED_KEY2;
			}

			/* Set up a break point with a do {} while (0) so that we can
				zeroize the sensitive buffers before exiting.
			 */
			do {
				if ((status = R_ComputeDHAgreedKey
				(agreedKey, gen_otherPublicValue, gen_privateValue, KEY_LENGTH, params))) {
					printf("ERROR: Code 0x%04x while computing agreed-upon key\n", status);
					break;
				}
			} while (0);

			printf("*** Agreed Key:  ");
			PrintBigInteger(agreedKey, params->primeLen);

			memset((POINTER)gen_privateValue, 0, KEY_LENGTH);
			memset((POINTER)agreedKey, 0, params->primeLen);
		}

	}

	R_memset((POINTER)(&randomStruct), 0, sizeof(randomStruct));

	//return(0);
	sc_stop();

}