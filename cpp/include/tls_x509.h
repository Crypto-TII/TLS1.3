
/**
 * @file tls_x509.h
 * @author Mike Scott
 * @brief X509 function Header File
 *
 * defines structures
 * declares functions
 *
 */

#ifndef TLS_X509_H
#define TLS_X509_H

// Supported Encryption Methods

#define X509_ECC 1      /**< Elliptic Curve data type detected */
#define X509_RSA 2      /**< RSA data type detected */
#define X509_ECD 3      /**< Elliptic Curve (Ed25519) detected */
#define X509_PQ 4       /**< Post Quantum method */
#define X509_HY 5       /**< Hybrid Post_Quantum */

// Supported Hash functions

#define X509_H256 2     /**< SHA256 hash algorithm used */
#define X509_H384 3     /**< SHA384 hash algorithm used */
#define X509_H512 4     /**< SHA512 hash algorithm used */

// Supported Curves

#define USE_NIST256 0    /**< For the NIST 256-bit standard curve - WEIERSTRASS only */
#define USE_C25519 1     /**< Bernstein's Modulus 2^255-19 - EDWARDS or MONTGOMERY only */
//#define USE_BRAINPOOL 2  /**< For Brainpool 256-bit curve - WEIERSTRASS only */
//#define USE_ANSSI 3      /**< For French 256-bit standard curve - WEIERSTRASS only */
#define USE_NIST384 10   /**< For the NIST 384-bit standard curve - WEIERSTRASS only */
#define USE_NIST521 12   /**< For the NIST 521-bit standard curve - WEIERSTRASS only */

extern octad X509_CN;  /**< Country Name */
extern octad X509_ON;  /**< organisation Name */
extern octad X509_EN;  /**< email */
extern octad X509_LN;  /**< local name */
extern octad X509_UN;  /**< Unit name (aka Organisation Unit OU) */
extern octad X509_MN;  /**< My Name (aka Common Name) */
extern octad X509_SN;  /**< State Name */

extern octad X509_AN;  /**< Alternate Name */
extern octad X509_KU;  /**< Key Usage */
extern octad X509_BC;  /**< Basic Constraints */

/**
 * @brief Public key type
 */
typedef struct
{
    int type;  /**< signature type (ECC or RSA) */
    int hash;  /**< hash type */
    int curve; /**< elliptic curve used or RSA key length in bits  */
} pktype;


/** @brief in-place ECDSA signature encoding
 *
    @param c an ecdsa signature to be converted from r|s form to ASN.1
*/
extern void ecdsa_sig_encode(octad *c);

/** @brief in-place ECDSA signature decoding
 *
    @param c an ecdsa signature to be converted from ASN.1 to simple r|s form
    @return index into c where conversion ended
*/
extern int ecdsa_sig_decode(octad *c);

/* X.509 functions */

/** @brief Extract private key
 *
	@param c an X.509 private key 
	@param pk the extracted private key - for RSA octad = p|q|dp|dq|c, for ECC octad = k
	@return 0 on failure, or indicator of private key type (ECC or RSA)
*/
extern pktype X509_extract_private_key(octad *c,octad *pk);

/** @brief Extract certificate signature
 *
	@param c an X.509 certificate
	@param s the extracted signature
	@return 0 on failure, or indicator of signature type (ECC or RSA)

*/
extern pktype X509_extract_cert_sig(octad *c, octad *s);
/** @brief
 *
	@param sc a signed certificate
	@param c the extracted certificate
	@return 0 on failure
*/
extern int X509_extract_cert(octad *sc, octad *c);
/** @brief
 *
	@param c an X.509 certificate
	@param k the extracted key
	@return 0 on failure, or indicator of public key type (ECC or RSA)
*/
extern pktype X509_extract_public_key(octad *c, octad *k);
/** @brief
 *
	@param c an X.509 certificate
	@return 0 on failure, or pointer to issuer field in cert
*/
extern int X509_find_issuer(octad *c);
/** @brief
 *
	@param c an X.509 certificate
	@return 0 on failure, or pointer to validity field in cert
*/
extern int X509_find_validity(octad *c);
/** @brief
 *
	@param c an X.509 certificate
	@return 0 on failure, or pointer to subject field in cert
*/
extern int X509_find_subject(octad *c);

/** @brief
 *
	@param c an X.509 certificate
	@return true if self-signed, else false
*/
extern int X509_self_signed(octad *c);

/** @brief
 *
	@param c an X.509 certificate
	@param S is OID of property we are looking for
	@param s is a pointer to the section of interest in the cert
	@param f is pointer to the length of the property
	@return 0 on failure, or pointer to the property
*/
extern int X509_find_entity_property(octad *c, octad *S, int s, int *f);
/** @brief
 *
	@param c an X.509 certificate
	@param s is a pointer to the start of the validity field
	@return 0 on failure, or pointer to the start date
*/
extern int X509_find_start_date(octad *c, int s);
/** @brief
 *
	@param c an X.509 certificate
	@param s is a pointer to the start of the validity field
	@return 0 on failure, or pointer to the expiry date
*/
extern int X509_find_expiry_date(octad *c, int s);

/** @brief
 *
	@param c an X.509 certificate
	@return 0 on failure (or no extensions), or pointer to extensions field in cert
*/
extern int X509_find_extensions(octad *c);
/** @brief
 *
	@param c an X.509 certificate
	@param S is OID of particular extension we are looking for
	@param s is a pointer to the section of interest in the cert
	@param f is pointer to the length of the extension
	@return 0 on failure, or pointer to the extension
*/
extern int X509_find_extension(octad *c, octad *S, int s, int *f);

/** @brief
 *
	@param c an X.509 certificate
    @param s is a pointer to certificate extension SubjectAltNames
    @param name is a URL
    @return 0 on failure, 1 if URL is in list of alt names
*/
extern int X509_find_alt_name(octad *c,int s,char *name);

#endif
