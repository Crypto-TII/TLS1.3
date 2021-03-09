// Client side C/C++ program to demonstrate TLS1.3 
// g++ -O2 -c tls*.cpp
// ar rc tls.a tls_protocol.o tls_keys_calc.o tls_sockets.o tls_cert_chain.o tls_client_recv.o tls_client_send.o tls_tickets.o tls_logger.o tls_cacerts.o
// g++ -O2 client.cpp tls.a core.a -o client

#include "tls1_3.h" 
#include "randapi.h"  
#include "tls_protocol.h"

#ifdef CORE_ARDUINO
#include "tls_wifi.h"
#endif

enum SocketType{
    SOCKET_TYPE_AF_UNIX,
    SOCKET_TYPE_AF_INET
};

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
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Waiting for Server input \n",NULL,0,NULL);
#endif
        OCT_clear(IO); ptr=0;
        type=getServerFragment(client,K_recv,IO);  // get first fragment to determine type
        if (type<0)
            return type;   // its an error
        if (type==TIME_OUT)
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"TIME_OUT\n",NULL,0,NULL);
#endif
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
#if VERBOSITY >= IO_PROTOCOL
                    logger((char *)"Got a ticket\n",NULL,0,NULL);
#endif
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
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"Something wrong\n",NULL,0,NULL);
#endif
                        return 0;
                    }
                    r=parseByteorPull(client,IO,ptr,K_recv); kur=r.val; if (r.err) break;
                    if (kur==0)
                    {
                        UPDATE_KEYS(K_recv,STS);  // reset record number
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"KEYS UPDATED\n",NULL,0,NULL);
#endif
                    }
                    if (kur==1)
                    {
                        UPDATE_KEYS(K_recv,STS);
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"Key update notified - client should do the same (?) \n",NULL,0,NULL);
                        logger((char *)"KEYS UPDATED\n",NULL,0,NULL);
#endif
                    }
                    if (ptr==IO->len) fin=true; // record finished
                    if (fin) break;
                    continue;

                default:
#if VERBOSITY >= IO_PROTOCOL
                    logger((char *)"Unsupported Handshake message type ",(char *)"%x",nb,NULL);
#endif
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
#if VERBOSITY >= IO_APPLICATION
            logger((char *)"Receiving application data (truncated HTML) = ",NULL,0,IO);
#endif
            return 0;
        }
        if (type==ALERT)
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Alert received from Server - type= ",NULL,0,IO);
#endif
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
void client_send(Socket &client,csprng *RNG,octet *GET,crypto *K_send,octet *IO)
{
#if VERBOSITY >= IO_APPLICATION
    logger((char *)"Sending Application Message\n\n",GET->val,0,NULL);
#endif
    sendClientMessage(client,RNG,APPLICATION,TLS1_2,K_send,GET,NULL,IO);
}

// Main Test Driver program
// 1. Connect to Website
// 2. Decide cryptographic capabilities
// 3. Do a Full TLS1.3 handshake
// 4. Attempt resumption with Early data 

// Some globals

capabilities CPB;
csprng RNG;                // Crypto Strong RNG
#ifdef ESP32
unsigned long ran=esp_random();   // ESP32 true random number generator
#else
unsigned long ran=42L;
#endif
int port;

#ifdef CORE_ARDUINO
char* ssid = "eir79562322-2.4G";
char* password =  "********";
char* hostname = "tls13.cloudfare.com";
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
    Serial.begin(115200); while (!Serial) ;
// make WiFi connection
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.print("\nWiFi connected with IP: ");
    Serial.println(WiFi.localIP());
#endif

    RAW.len = 100;              // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++) RAW.val[i] = i;

    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG

#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Hostname= ",hostname,0,NULL);
#endif
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
        ,  26624  // 32K-6K This stack size can be checked & adjusted by reading the Stack Highwater
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
                    Socket::UnixSocket():
                    Socket::InetSocket();

    if (!client.connect(hostname,port))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Unable to access ",hostname,0,NULL);
#endif
        mydelay();
 		return;
    }

// Do full TLS 1.3 handshake
    rtn=TLS13_full(client,hostname,RNG,favourite_group,CPB,IO,RMS,T,K_send,K_recv,STS);
    if (rtn)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake succeeded\n",NULL,0,NULL);
        if (rtn==2) logger((char *)"... after handshake resumption\n",NULL,0,NULL);
#endif
    }
    else {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        mydelay();
        return;
    }

// Send client message
    client_send(client,&RNG,&GET,&K_send,&IO);

// Process server responses
    rtn=processServerMessage(client,&IO,&K_recv,&STS,&T); 
    if (rtn<0)
        sendClientAlert(client,&RNG,alert_from_cause(rtn),&K_send,&IO);

    client.stop();
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Connection closed\n",NULL,0,NULL);
#endif
// reopen socket - attempt resumption
    if (T.lifetime==0)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"No Ticket provided - unable to resume\n",NULL,0,NULL);
#endif
        mydelay();
        return;
    }
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"\nAttempting resumption\n",NULL,0,NULL);
#endif
    if (!client.connect(hostname,port))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"\nConnection Failed \n",NULL,0,NULL); 
#endif
        mydelay();
        return;
    }
// Resume connection. Try and send early data in GET
    rtn=TLS13_resume(client,hostname,RNG,favourite_group,CPB,IO,RMS,T,K_send,K_recv,STS,GET);
    if (rtn)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake succeeded\n",NULL,0,NULL);
        if (rtn==2) logger((char *)"Early data was accepted\n",NULL,0,NULL);
#endif
    } else {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        mydelay();
        return;
    }

// Send client message again - if it failed to go as early data
    if (rtn!=2)
        client_send(client,&RNG,&GET,&K_send,&IO);

// Process server responses
    rtn=processServerMessage(client,&IO,&K_recv,&STS,&T); 
    if (rtn<0)
        sendClientAlert(client,&RNG,alert_from_cause(rtn),&K_send,&IO);

    client.stop();  // After time out, exit and close session
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Connection closed\n",NULL,0,NULL);
#endif
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
    if(argc==0)
    {
        strcpy(hostname, "localhost");
        port = 4433;
    } else if (argc == 1)
    {
        bool contains_colon = false;
        
        int i;
        size_t argv0_len = strlen(argv[0]);
        for(i =0; i < argv0_len; ++i)
        {
            if(argv[0][i] == ':')
            {
                contains_colon = true;
                break;
            }
        }
        
        if(contains_colon)
        {
            strncpy(hostname, argv[0], i);
            char port_part[5];
            strncpy(port_part, argv[0]+sizeof(char)*(i+1), (argv0_len - i));
            port = atoi(port_part);
            printf("Host: %s, Port: %d", hostname, port);
        } else {
            strcpy(hostname, argv[0]);
            port = 443;
        }
    } else if (argc == 2) {
        if(strncasecmp(argv[0], "AF_UNIX", strlen("AF_UNIX")) == 0){
            logger((char*) "AF_UNIX mode\n", NULL, 0, NULL);
            socketType = SocketType::SOCKET_TYPE_AF_UNIX;
            strcpy(hostname, argv[1]);
        } else {
            logger((char*) "AF_UNIX mode requires: AF_UNIX $socketname", NULL, 0, NULL);
            exit(EXIT_FAILURE);
        }
    } else {
        logger((char*) "Did not understand your request. Cannot proceed with request.", NULL, 0, NULL);
        exit(EXIT_FAILURE);
    }
    time((time_t *)&ran);
    setup();
    loop();  // just once
}
#endif
