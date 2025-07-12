/**
 * @file tls_certs.h
 * @author Mike Scott
 * @brief Certificate Authority root certificate store
 *
 */

#ifndef TLS_CA_CERTS_H
#define TLS_CA_CERTS_H

#include "tls1_3.h"

//extern const char *mysupportedca;  /**< Supported root CA */
extern const char *myprivate; /**< Client private key */
extern const char *mycert;    /**< Client certificate */
extern const char *cacerts;   /**< The Root Certificate store */

using namespace std;

/** @brief Extract certificate chain and secret key from client credentials (either stored or from file 
 *
    @param Credential the client credential structure to be filled
    @return false if client not equipped (via SAL) to implement signature 
 */
extern bool setCredential(credential *Credential);

#endif
