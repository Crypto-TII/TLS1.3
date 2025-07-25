/**
 * @file tls_protocol.h
 * @author Mike Scott
 * @brief TLS 1.3 main client-side protocol functions
 *
 */
// Main TLS 1.3 Protocol

#ifndef TLS_PROTOCOL_H
#define TLS_PROTOCOL_H

#include "tls1_3.h" // for sockets, octads and session structure


/** @brief initialise a TLS 1.3 session structure
 *
    @param client the socket connection to the Server
    @param hostname the host name (URL) of the server
    @return an initialised TLS1.3 session structure
 */
extern TLS_session TLS13_start(Socket *client,char *hostname);

/** @brief terminate a session structure
 *
    @param session the session structure
 */
extern void TLS13_end(TLS_session *session);


/** @brief stop sending - send CLOSE_NOTIFY and DISCONNECT
 *
    @param session the session structure
 */
extern void TLS13_stop(TLS_session *session);


/** @brief TLS 1.3 forge connection
 *
    @param session an initialised TLS session structure
    @param EARLY some early data to be transmitted
    @param Credential client credential    
    @return false for failure, true for success
 */
extern bool TLS13_connect(TLS_session *session,octad *EARLY,credential *Credential);

/**    @brief TLS 1.3 send data
 *
    @param session an initialised TLS session structure
    @param DATA some data to be transmitted
 */
extern void TLS13_send(TLS_session *session,octad *DATA);

/** @brief TLS 1.3 receive data
 *
    @param session an initialised TLS session structure
    @param DATA that has been received
    @param Credential client credential    
    @return 0 for time-out, negative for error, or length of data successfully received
 */
extern int TLS13_recv(TLS_session *session,octad *DATA,credential *Credential);

/** @brief TLS 1.3 receive data and check for liveness of connection
 *
    @param session an initialised TLS session structure
    @param DATA that has been received
    @return 0 for time-out, negative for error, or length of data successfully received
 */
extern int TLS13_recv_and_check(TLS_session *session,octad *DATA);


/** @brief TLS 1.3 end session, delete keys, clean up buffers
 *
    @param session an initialised TLS session structure
 */
extern void TLS13_clean(TLS_session *session);
#endif
