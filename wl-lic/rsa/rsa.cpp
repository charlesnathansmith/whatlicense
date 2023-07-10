/*****
*
* WL File Key Demo
*
* Bare-bones RSA implementation to handle license signing and encryption
*
 *****/

#include <cstdint>
#include <memory>
#include "libtommath/tommath.h"
#include "sha1/sha1.h"
#include "rsa_key.h"
#include "rsa.h"

// Computes SHA-1 digest
// out needs to hold 20 bytes
void sha1(uint8_t* const in, size_t in_size, uint8_t* out)
{
	SHA1_CTX sha;

	SHA1Init(&sha);
	SHA1Update(&sha, in, in_size);
	SHA1Final(out, &sha);
}

// Generate SHA-1 message for RSA signing
// out buffer must be able to hold mod_size bytes
bool rsa_sha1_msg(uint8_t* const in, size_t in_size, size_t mod_size, uint8_t* out)
{
	// Non-padding bytes
	// header len + padding end marker len + SHA-1 DER identifier len + sha1 digest len
	size_t unpadded_len = 2 + 1 + 15 + 20;
	size_t pad_len = mod_size - unpadded_len;

	// This should never happen
	if (mod_size < unpadded_len)
		return false;

	// Message header
	*out++ = 0x00;
	*out++ = 0x01;

	// Padding
	for (size_t i = 0; i < pad_len; i++)
		*out++ = 0xff;

	// End of padding marker
	*out++ = 0x00;

	// SHA-1 algorithm identifier
	static const uint8_t sha_id[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
									  0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };

	memcpy(out, sha_id, 15);
	out += 15;

	// SHA-1 digest
	sha1(in, in_size, out);

	return true;
}

// Central RSA encryption routine
bool rsa_exptmod(uint8_t* const in, size_t in_size, rsa_private_key& key, uint8_t* out, size_t* out_size)
{
	size_t written;

	mp_int msg;
	mp_init(&msg);

	// Convert message (in) to mp_int
	if (mp_from_ubin(&msg, in, in_size) != CRYPT_OK)
		goto error;

	// RSA encrypt
	if (mp_exptmod(&msg, key.exp(), key.n(), &msg) != CRYPT_OK)
		goto error;

	// Make sure out buffer is large enough and set write size
	written = mp_ubin_size(key.n());
	
	if (written > *out_size)
		goto error;

	*out_size = written;

	// Convert message back to byte stream
	if (mp_to_ubin(&msg, out, *out_size, &written) != CRYPT_OK)
		goto error;

	mp_clear(&msg);
	return true;

error:
	mp_clear(&msg);
	return false;
}

// RSA sign a message using SHA-1
bool rsa_sign(uint8_t* const in, size_t in_size, rsa_private_key& key, uint8_t* out, size_t out_size)
{
	size_t mod_size = key.size();

	if (out_size < mod_size)
		return false;

	// Build hash message to sign
	uint8_t *sig_msg = new uint8_t[mod_size];

	if (!rsa_sha1_msg(in, in_size, mod_size, sig_msg))
	{
		delete[] sig_msg;
		return false;
	}

	// Encrypt hash message
	return rsa_exptmod(sig_msg, mod_size, key, out, &out_size);
	
	delete[] sig_msg;
	return true;
}
