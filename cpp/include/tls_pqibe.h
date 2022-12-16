#ifndef IBE_H
#define IBE_H

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