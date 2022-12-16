/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BFIBE_BLS381_H
#define BFIBE_BLS381_H

#include "pair_BLS12381.h"

using namespace core;

/* Field size is assumed to be greater than or equal to group size */

#define PGS_BLS12381 MODBYTES_B384_58  /**< MPIN Group Size */
#define PFS_BLS12381 MODBYTES_B384_58  /**< MPIN Field Size */

#define IBE_OK             0    /**< Function completed without error */
#define IBE_INVALID_POINT  -14	/**< Point is NOT on the curve */
#define IBE_FAIL           -19  /**< IBE failed */

/* IBE primitives */

/**	@brief Create key SSK encapsulated in ciphertext CT to be sent to ID
 *
	@param ID the entity to receive encapsulated key
	@param R32 32 random bytes
	@param SSK is the encapsulated key
	@param CT is the ciphertext
	@return 0 or an error code
 */
bool BFIBE_CCA_ENCRYPT(char *ID,octet *R32,octet *SSK,octet *CT);

/**	@brief Create key SSK encapsulated in ciphertext CT to be sent to ID
 *
	@param SK the secret key of ID
	@param CT is the ciphertext
	@param SSK is the decapsulated key
	@return 0 or an error code
 */
bool BFIBE_CCA_DECRYPT(octet *SK,octet *CT,octet *SSK);

#endif

