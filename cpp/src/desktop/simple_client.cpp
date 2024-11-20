// simple_client C++ program to demonstrate TLS1.3 - connects to TiigerTLS server running on localhost

#include "tls_protocol.h"

enum SocketType{
    SOCKET_TYPE_AF_UNIX,
    SOCKET_TYPE_AF_INET
};

int main(int argc, char const *argv[])
{
    char hostname[TLS_MAX_SERVER_NAME];
    char resp[80];
    octad RESP={0,sizeof(resp),resp};  // response (will be truncated)
    char mess[80];
    octad MESS={0,sizeof(mess),mess};
    OCT_append_string(&MESS,(char *)"Hello Server");

    int port=4433;
    SocketType socketType = SocketType::SOCKET_TYPE_AF_INET;
    Socket client = (socketType == SocketType::SOCKET_TYPE_AF_UNIX) ?
                    Socket::UnixSocket():
                    Socket::InetSocket();
    strcpy(hostname, "localhost");

    if (!client.connect(hostname,port))
    {
        printf("Unable to connect to localhost ");
 		return 0;
    }
    printf("Local Port= %d\n",client.getport());

// create new session
    TLS_session state=TLS13_start(&client,hostname);
    TLS_session *session=&state;

// Make TLS connection
    if (!TLS13_connect(session,NULL))
    { 
        printf("TLS Handshake failed\n");
        TLS13_stop(session);
        TLS13_end(session);
        client.stop();
        return 0;
    }
    
// Send and receive some messages
    for (int i=0;i<10;i++)
    {
        printf("Sending Message:  %s",MESS.val); printf("\n");
        TLS13_send(session,&MESS);
        int rtn=TLS13_recv(session,&RESP);
        if (rtn>0) {
            printf("Received Message: %s",RESP.val); printf("\n");
        } else break;
    }
    TLS13_stop(session);
    TLS13_end(session);
    client.stop();
    return 0;
}
