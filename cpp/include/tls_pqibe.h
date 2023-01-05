/**
 * @file tls_pqibe.h
 * @author Mike Scott
 * @brief Ducas et al. IBE
 *
 */
//
// Lattice-based B&F IBE 128-bit API Functions 
// Ducas et al. Method
// Implementation by M.Scott
//

#ifndef PQIBE_H
#define PQIBE_H

#include "core.h"

using namespace core;

/** @brief IBE KEM CCA encrypt
 *
    @param ID Identity
    @param R32 32 random bytes
	@param KEY random session key generated
	@param CT encapsulating ciphertext
 */
extern void PQIBE_CCA_ENCRYPT(char *ID,octet *R32,octet *KEY,octet *CT);

/** @brief IBE KEM CCA decrypt
 *
    @param ID Identity
    @param csk secret key
	@param CT ciphertext
	@param KEY output session key 
 */
extern void PQIBE_CCA_DECRYPT(char *ID,const int16_t *csk,octet *CT,octet *KEY);

#endif