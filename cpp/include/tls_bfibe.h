/**
 * @file tls_bfibe.h
 * @author Mike Scott
 * @brief Boneh and Franklin IBE
 *
 */
//
// Pairing-based B&F IBE 128-bit API Functions
// Uses MIRACL
//
#ifndef BFIBE_BLS381_H
#define BFIBE_BLS381_H

#include "pair_BLS12381.h"

using namespace core;

/* Field size is assumed to be greater than or equal to group size */

#if CHUNK == 32
#define PGS_BLS12381 MODBYTES_B384_29  /**< BF Group Size */
#define PFS_BLS12381 MODBYTES_B384_29  /**< BF Field Size */
#else
#define PGS_BLS12381 MODBYTES_B384_58  /**< BF Group Size */
#define PFS_BLS12381 MODBYTES_B384_58  /**< BF Field Size */
#endif

/* IBE primitives */

/** @brief Create key SSK encapsulated in ciphertext CT to be sent to ID
 *
    @param ID the entity to receive encapsulated key
    @param R32 32 random bytes
    @param SSK is the encapsulated key
    @param CT is the ciphertext
    @return true if OK
 */
bool BFIBE_CCA_ENCRYPT(char *ID,octet *R32,octet *SSK,octet *CT);

/** @brief Create key SSK encapsulated in ciphertext CT to be sent to ID
 *
    @param SK the secret key of ID
    @param CT is the ciphertext
    @param SSK is the decapsulated key
    @return true if OK
 */
bool BFIBE_CCA_DECRYPT(octet *SK,octet *CT,octet *SSK);

#endif

