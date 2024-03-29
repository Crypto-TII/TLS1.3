
// Set up and read/write sockets

#include "tls_logger.h"

#ifndef TLS_ARDUINO

//int BYTES_READ=0;
//int BYTES_WRITTEN=0;

// open socket
int setclientsock(int port,char *ip,int toms)
{
    int sock = 0; 
    struct sockaddr_in serv_addr; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        return -1; 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(port); 
       
// Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)  
        return -2; 
   
// Set time-out period    
    struct timeval timeout;

    timeout.tv_sec  = toms/1000;  // after some seconds read() will timeout
    timeout.tv_usec = (toms%1000)*1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
        return -3; 
    
    return sock;
}

// get IP address from Hostname
int getIPaddress(char *ip,char *hostname)
{
    hostent * record = gethostbyname(hostname);
    if(record == NULL) return 0;
    in_addr * address = (in_addr * )record->h_addr;
    strcpy(ip,inet_ntoa(* address));
    return 1;
}

#endif

// Send Octet
void sendOctad(Socket *client,octad *B)
{
    client->write(B->val,B->len);
//BYTES_WRITTEN+=B->len;

#if VERBOSITY >= IO_WIRE

    char w[4];
    myprintf((char *)"-> ");
    for (int j = 0; j < B->len; j++)
    {
        sprintf(w,"%02x", (unsigned char)B->val[j]);
        myprintf(w);
    }
    myprintf((char *)"\n");

#endif    
}

// Send Octet length
void sendLen(Socket *client,int len)
{
    char buff[2];
    octad B={0, sizeof(buff), buff};
    B.len=2;
    B.val[0]=len&0xff;
    B.val[1]=len/256;
    sendOctad(client,&B);
}


#ifdef TLS_ARDUINO

// clear out the socket RX buffer
void clearsoc(Socket &client,octad *IO)
{
    int n=client.available();
    client.read((uint8_t *)IO->val,n);
    OCT_kill(IO);
}

#endif

// get expected bytes
int getBytes(Socket *client,char *b,int expected)
{
    int n,more,i=0,len=expected;

//BYTES_READ+=expected;

#ifdef TLS_ARDUINO

    unsigned long start=millis();
    while (len>0)
    {
        if (millis()>start+5000)
            return -1;
        n=client->available();
        if (n==0) continue;  // nothing there
        if (n>len) n=len;    // possibly more than I need right now
        client->read((uint8_t *)&b[i],n);
        i+=n;
        len-=n;
    }

#else
    unsigned long start=millis();
    while(len>0)
    {
        if (millis()>start+5000)
            return -1;
        more=client->read(&b[i],len);
        if (more==0) continue;
        if (more<0) return -1;
        i+=more;
        len-=more;
    }
#endif

#if VERBOSITY >= IO_WIRE

    char w[4];
    myprintf((char *)"<- ");
    for (int j = 0; j < expected; j++)
    {
        sprintf(w,"%02x", (unsigned char)b[j]);
        myprintf(w);
    }
    myprintf((char *)"\n");

#endif
    return 0;
}

// Get 16-bit Integer from stream
int getInt16(Socket *client)
{
    char b[2];
    getBytes(client,b,2);
    return 256*(int)(unsigned char)b[0]+(int)(unsigned char)b[1];
}

// Get expected number of bytes into an octet
int getOctad(Socket *client,octad *B,int expected)
{
    B->len=expected;
    return getBytes(client,B->val,expected);
}

