/**
 * @file tls_cacerts.h
 * @author Mike Scott
 * @brief Certificate Authority root certificate store
 *
 */

#ifndef TLS_CA_CERTS_H
#define TLS_CA_CERTS_H

#include "tls1_3.h"

extern const char *myprivate; /**< Client private key */
extern const char *mycert;    /**< Client certificate */
extern const char *cacerts;   /**< The Root Certificate store */

#endif
