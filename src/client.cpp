// Client side C/C++ program to demonstrate TLS1.3 
// g++ -O2 client.cpp tls_protocol.cpp tls_keys_calc.cpp tls_sockets.cpp tls_cert_chain.cpp  tls_client_recv.cpp tls_client_send.cpp tls_tickets.cpp tls_logger.cpp tls_cacerts.cpp core.a -o client

#include "tls1_3.h" 
#include "randapi.h"  
#include "tls_protocol.h"

#ifdef CORE_ARDUINO
#include <WiFi.h>
#endif

enum SocketType{
    SOCKET_TYPE_AF_UNIX,
    SOCKET_TYPE_AF_INET
};


//#define ESP32

// Process Server records received post-handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
// Extract a ticket. K_recv might be updated.
int processServerMessage(Socket &client,octet *IO,crypto *K_recv,octet *STS,ticket *T)
{
    ret r;
    int nce,nb,len,te,type,nticks,kur,ptr=0;
    bool fin=false;
    unsign32 time_ticket_received;
    octet TICK;  // Ticket raw data
    TICK.len=0;

    nticks=0; // number of tickets received
    while (1)
    {
        logger(IO_PROTOCOL,(char *)"Waiting for Server input \n",NULL,0,NULL);
        OCT_clear(IO); ptr=0;
        type=getServerFragment(client,K_recv,IO);  // get first fragment to determine type
        if (type<0)
            return type;   // its an error
        if (type==TIME_OUT)
        {
            logger(IO_PROTOCOL,(char *)"TIME_OUT\n",NULL,0,NULL);
            break;
        }
        if (type==HSHAKE)
        {
            while (1)
            {
                r=parseByteorPull(client,IO,ptr,K_recv); nb=r.val; if (r.err) return r.err;
                r=parseInt24orPull(client,IO,ptr,K_recv); len=r.val; if (r.err) return r.err;   // message length
                switch (nb)
                {
                case TICKET :   // keep last ticket
                    logger(IO_PROTOCOL,(char *)"Got a ticket\n",NULL,0,NULL);
                    r=parseOctetorPullptr(client,&TICK,len,IO,ptr,K_recv);    // just copy out pointer to this
                    nticks++;
                    time_ticket_received=(unsign32)millis();     // start a stop-watch
                    init_ticket_context(T,time_ticket_received); // initialise and time-stamp a new ticket
                    parseTicket(&TICK,T);  // extract into ticket structure, and keep for later use
                    if (ptr==IO->len) fin=true; // record finished
                    if (fin) break;
                    continue;
               case KEY_UPDATE :
                    if (len!=1)
                    {
                        logger(IO_PROTOCOL,(char *)"Something wrong\n",NULL,0,NULL);
                        return 0;
                    }
                    r=parseByteorPull(client,IO,ptr,K_recv); kur=r.val; if (r.err) break;
                    if (kur==0)
                    {
                        UPDATE_KEYS(K_recv,STS);  // reset record number
                        logger(IO_PROTOCOL,(char *)"KEYS UPDATED\n",NULL,0,NULL);
                    }
                    if (kur==1)
                    {
                        logger(IO_PROTOCOL,(char *)"Key update notified - client should do the same (?) \n",NULL,0,NULL);
                        UPDATE_KEYS(K_recv,STS);
                        logger(IO_PROTOCOL,(char *)"KEYS UPDATED\n",NULL,0,NULL);
                    }
                    if (ptr==IO->len) fin=true; // record finished
                    if (fin) break;
                    continue;

                default:
                    logger(IO_PROTOCOL,(char *)"Unsupported Handshake message type ",(char *)"%x",nb,NULL);
                    fin=true;
                    break;            
                }
                if (r.err) return r.err;
                if (fin) break;
            }
        }
        if (type==APPLICATION)
        {
            OCT_chop(IO,NULL,40);   // truncate it to 40 bytes
            logger(IO_APPLICATION,(char *)"Receiving application data (truncated HTML) = ",NULL,0,IO);
            return 0;
        }
        if (type==ALERT)
        {
            logger(IO_PROTOCOL,(char *)"Alert received from Server - type= ",NULL,0,IO);
            return 0;
        }
    }
    return 0;
}

// Construct an HTML GET command
void make_client_message(octet *GET,char *hostname)
{
    OCT_clear(GET);
    OCT_jstring(GET,(char *)"GET / HTTP/1.1"); // standard HTTP GET command  
    OCT_jbyte(GET,0x0d,1); OCT_jbyte(GET,0x0a,1);      
    OCT_jstring(GET,(char *)"Host: ");  
    OCT_jstring(GET,hostname); //OCT_jstring(&PT,(char *)":443");
    OCT_jbyte(GET,0x0d,1); OCT_jbyte(GET,0x0a,1);        // CRLF
    OCT_jbyte(GET,0x0d,1); OCT_jbyte(GET,0x0a,1);        // empty line CRLF    
}

// send a message post-handshake
void client_send(Socket &client,octet *GET,crypto *K_send,octet *IO)
{
    logger(IO_APPLICATION,(char *)"Sending Application Message\n\n",GET->val,0,NULL);
    sendClientMessage(client,APPLICATION,TLS1_2,K_send,GET,NULL,IO);
}

// Main program
// 1. Connect to Website
// 2. Decide cryptographic capabilities
// 3. Do a Full TLS1.3 handshake
// 4. Attempt resumption with Early data 

// Some globals

#ifndef CORE_ARDUINO
unsigned long esp_random(){
    return 1UL;
}
#endif

capabilities CPB;
csprng RNG;                // Crypto Strong RNG
#ifdef ESP32
unsigned long ran=esp_random();   // ESP32 true random number generator
#else
unsigned long ran=42L;
#endif
int port;

#ifdef CORE_ARDUINO
const char* ssid = "eir79562322-2.4G";
const char* password =  "uzy987ru";
char* hostname = "www.bbc.co.uk";
void mydelay()
{
    while (1) delay(1000);
}
#else
char hostname[TLS_MAX_SERVER_NAME];
void mydelay()
{}
#endif
SocketType socketType = SocketType::SOCKET_TYPE_AF_INET;


#ifdef ESP32
#if CONFIG_FREERTOS_UNICORE
#define ARDUINO_RUNNING_CORE 0
#else
#define ARDUINO_RUNNING_CORE 1
#endif
void myloop( void *pvParameters );
#endif


// This rather strange program structure is required by the Arduino development environment
// A hidden main() functions calls setup() once, and then repeatedly calls loop()
// This actually makes a lot of sense in an embedded environment

// This structure does however mean that a certain of amount of global data is inevitable

void setup()
{
    char raw[100];
    octet RAW = {0, sizeof(raw), raw}; // Some initial entropy

#ifdef CORE_ARDUINO
    Serial.begin(115200);
// make WiFi connection
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.println("...");
    }
    Serial.print("WiFi connected with IP: ");
    Serial.println(WiFi.localIP());
#endif

    RAW.len = 100;              // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++) RAW.val[i] = i;

    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG

    port=443;
    logger(IO_PROTOCOL,(char *)"Hostname= ",hostname,0,NULL);

// Client Capabilities to be advertised to Server
// Supported Key Exchange Groups in order of preference
    CPB.nsg=3;
    CPB.supportedGroups[0]=X25519;
    CPB.supportedGroups[1]=SECP256R1;
    CPB.supportedGroups[2]=SECP384R1;

// Supported Cipher Suits
    CPB.nsc=2;     
    CPB.ciphers[0]=TLS_AES_128_GCM_SHA256;
    CPB.ciphers[1]=TLS_AES_256_GCM_SHA384;
  //  ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not supported

// Extensions
// Supported Cert signing Algorithms - could add more
    CPB.nsa=8;
    CPB.sigAlgs[0]=ECDSA_SECP256R1_SHA256;
    CPB.sigAlgs[1]=RSA_PSS_RSAE_SHA256;
    CPB.sigAlgs[2]=RSA_PKCS1_SHA256;
    CPB.sigAlgs[3]=ECDSA_SECP384R1_SHA384;
    CPB.sigAlgs[4]=RSA_PSS_RSAE_SHA384;
    CPB.sigAlgs[5]=RSA_PKCS1_SHA384;
    CPB.sigAlgs[6]=RSA_PSS_RSAE_SHA512;
    CPB.sigAlgs[7]=RSA_PKCS1_SHA512;
    CPB.sigAlgs[8]=RSA_PKCS1_SHA1;

#ifdef ESP32
    xTaskCreatePinnedToCore(
        myloop
        ,  "client"   // A name just for humans
        ,  28672  // 32K-4K This stack size can be checked & adjusted by reading the Stack Highwater
        ,  NULL
        ,  3  // Priority, with 3 (configMAX_PRIORITIES - 1) being the highest, and 0 being the lowest.
        ,  NULL 
        ,  ARDUINO_RUNNING_CORE);
#endif

}

// Try for a full handshake - disconnect - try to resume connection - repeat
#ifdef ESP32
void loop()
{
}

void myloop(void *pvParameters) {
    (void) pvParameters;
#else
void loop() {
#endif
    int rtn,favourite_group;
    char rms[TLS_MAX_HASH];
    octet RMS = {0,sizeof(rms),rms};   // Resumption master secret
    char sts[TLS_MAX_HASH];
    octet STS = {0,sizeof(sts),sts};   // server traffic secret
    char io[TLS_MAX_IO_SIZE];
    octet IO={0,sizeof(io),io};        // main IO buffer - all messages come and go via this octet   --- BIG
    char get[256];
    octet GET={0,sizeof(get),get};     // initial message
    ticket T;
    crypto K_send, K_recv;             // crypto contexts, sending and receiving

    init_crypto_context(&K_send);
    init_crypto_context(&K_recv);
    make_client_message(&GET,hostname);

    Socket client = (socketType == SocketType::SOCKET_TYPE_AF_UNIX) ?
            Socket::UnixSocket(hostname) :
            Socket::InetSocket(hostname, port);

    if (!client.isConnected())
    {
        logger(IO_PROTOCOL,(char *)"Unable to access ",hostname,0,NULL);
        mydelay();
 		return;
    }

// Do full TLS 1.3 handshake
    rtn=TLS13_full(client,hostname,RNG,favourite_group,CPB,IO,RMS,T,K_send,K_recv,STS);
    if (rtn)
    {
        logger(IO_PROTOCOL,(char *)"Full Handshake succeeded\n",NULL,0,NULL);
        if (rtn==2) logger(IO_PROTOCOL,(char *)"... after handshake resumption\n",NULL,0,NULL);
    }
    else {
        logger(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
        mydelay();
        return;
    }

// Send client message
    client_send(client,&GET,&K_send,&IO);

// Process server responses
    rtn=processServerMessage(client,&IO,&K_recv,&STS,&T); 
    if (rtn<0)
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);

    client.stop();
    logger(IO_PROTOCOL,(char *)"Connection closed\n",NULL,0,NULL);

// reopen socket - attempt resumption
    if (T.lifetime==0)
    {
        logger(IO_PROTOCOL,(char *)"No Ticket provided - unable to resume\n",NULL,0,NULL);
        mydelay();
        return;
    }

    logger(IO_PROTOCOL,(char *)"\nAttempting resumption\n",NULL,0,NULL);

    if (!client.isConnected())
    {
        logger(IO_PROTOCOL,(char *)"\nConnection Failed \n",NULL,0,NULL); 
        mydelay();
        return;
    }
// Resume connection. Try and send early data in GET
    rtn=TLS13_resume(client,hostname,RNG,favourite_group,CPB,IO,RMS,T,K_send,K_recv,STS,GET);
    if (rtn)
    {
        logger(IO_PROTOCOL,(char *)"Resumption Handshake succeeded\n",NULL,0,NULL);
        if (rtn==2) logger(IO_PROTOCOL,(char *)"Early data was accepted\n",NULL,0,NULL);
    } else {
        logger(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
        mydelay();
        return;
    }

// Send client message again - if it failed to go as early data
    if (rtn!=2)
        client_send(client,&GET,&K_send,&IO);

// Process server responses
    rtn=processServerMessage(client,&IO,&K_recv,&STS,&T); 
    if (rtn<0)
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);

    client.stop();  // After time out, exit and close session
    logger(IO_PROTOCOL,(char *)"Connection closed\n",NULL,0,NULL);

#ifdef ESP32
    Serial.print("Amount of unused stack memory ");
      Serial.println(uxTaskGetStackHighWaterMark( NULL ));
#endif
    mydelay();
}

#ifndef CORE_ARDUINO
int main(int argc, char const *argv[])
{
    argv++; argc--;
    socketType = SocketType::SOCKET_TYPE_AF_INET;
    if (argc == 1) {
        strcpy(hostname, argv[0]);
        port = 443;
    } else if (argc == 2) {
        if(strncasecmp(argv[0], "AF_UNIX", strlen("AF_UNIX")) == 0){
            logger(IO_APPLICATION, (char*) "AF_UNIX mode\n", NULL, 0, NULL);
            socketType = SocketType::SOCKET_TYPE_AF_UNIX;
            strcpy(hostname, argv[1]);
        } else {
            logger(IO_APPLICATION, (char*) "AF_UNIX mode requires: AF_UNIX $socketname", NULL, 0, NULL);
            exit(EXIT_FAILURE);
        }
    } else {
        strcpy(hostname, "localhost");
        port = 4433;
    }
    time((time_t *)&ran);
    setup();
    loop();  // just once
}
#endif
