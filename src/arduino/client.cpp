// Client side C/C++ program to demonstrate TLS1.3 
// Arduino Version

#include "tls_sal.h"
#include "tls_protocol.h"
#include "tls_wifi.h"

// Process Server records received post-handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
// Extract a ticket. Receiving key K_recv might be updated.
int processServerMessage(Socket &client,octad *IO,crypto *K_recv,octad *STS,ticket *T)
{
    ret r;
    int nce,nb,len,te,type,nticks,kur,rtn,ptr=0;
    bool fin=false;
    unsign32 time_ticket_received;
    octad TICK;  // Ticket raw data
    TICK.len=0;

    nticks=0; // number of tickets received
    while (1)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Waiting for Server input \n",NULL,0,NULL);
#endif
        OCT_kill(IO); ptr=0;
        type=getServerFragment(client,K_recv,IO);  // get first fragment to determine type
        if (type<0)
            return type;   // its an error
        if (type==TIMED_OUT)
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

//printf("Ticket length= %d %d\n",ptr,len);

                    r=parseoctadorPullptr(client,&TICK,len,IO,ptr,K_recv);    // just copy out pointer to this
                    nticks++;
                    rtn=parseTicket(&TICK,(unsign32)millis(),T);       // extract into ticket structure T, and keep for later use
//printf("Error return= %d\n",rtn);
                    
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
                        deriveUpdatedKeys(K_recv,STS);  // reset record number
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"KEYS UPDATED\n",NULL,0,NULL);
#endif
                    }
                    if (kur==1)
                    {
                        deriveUpdatedKeys(K_recv,STS);
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
            OCT_truncate(IO,40); // truncate it to 40 bytes
#if VERBOSITY >= IO_APPLICATION
            logger((char *)"Receiving application data (truncated HTML) = ",NULL,0,IO);
#endif
            return 0;
        }
        if (type==ALERT)
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"*** Alert received - ",NULL,0,NULL);
            logAlert(IO->val[1]);
#endif
            return 0;
        }
    }
    return 0;
}

// Construct an HTML GET command
void make_client_message(octad *GET,char *hostname)
{
    OCT_kill(GET);
    OCT_append_string(GET,(char *)"GET / HTTP/1.1"); // standard HTTP GET command  
    OCT_append_byte(GET,0x0d,1); OCT_append_byte(GET,0x0a,1);      
    OCT_append_string(GET,(char *)"Host: ");  
    OCT_append_string(GET,hostname); //OCT_append_string(&PT,(char *)":443");
    OCT_append_byte(GET,0x0d,1); OCT_append_byte(GET,0x0a,1);        // CRLF
    OCT_append_byte(GET,0x0d,1); OCT_append_byte(GET,0x0a,1);        // empty line CRLF    
}

// send a message post-handshake
void client_send(Socket &client,octad *GET,crypto *K_send,octad *IO)
{
#if VERBOSITY >= IO_APPLICATION
    logger((char *)"Sending Application Message\n\n",GET->val,0,NULL);
#endif
    sendClientMessage(client,APPLICATION,TLS1_2,K_send,GET,NULL,IO);
}

// Main Test Driver program
// 1. Connect to Website
// 2. Decide cryptographic capabilities
// 3. Do a Full TLS1.3 handshake
// 4. Attempt resumption with Early data 

// Some globals

capabilities CPB;
int port=443;

char* ssid = (char *)"eir79562322-2.4G";
char* password =  (char *)"********";
char* hostname = (char *)"www.bbc.co.uk";  // HTTPS TLS1.3 server
void mydelay()
{
    while (1) delay(1000);
}

// make connection, using full handshake, resumption, or PSK.
// Full handshake may provide a ticket, stored in file cookie.txt
// Resumption mode consumes a ticket, and may provide one
// For Arduino, just maintain last ticket in memory, and perform immediate resumption
static void makeConnection(Socket client,int mode,ticket &T)
{
    int rtn,favourite_group,cipher_suite;
    char rms[TLS_MAX_HASH];
    octad RMS = {0,sizeof(rms),rms};   // Resumption master secret
    char sts[TLS_MAX_HASH];
    octad STS = {0,sizeof(sts),sts};   // server traffic secret
    char io[TLS_MAX_IO_SIZE];
    octad IO={0,sizeof(io),io};        // main IO buffer - all messages come and go via this octad   --- BIG!
    char get[256];
    octad GET={0,sizeof(get),get};     // initial message
    crypto K_send, K_recv;             // crypto contexts, sending and receiving
    bool HAVE_PSK=false;
    int origin;

    initCryptoContext(&K_send);
    initCryptoContext(&K_recv);
    make_client_message(&GET,hostname);

// clear out the socket RX buffer
    clearsoc(client,&IO);

    switch (mode)
    {

    case TLS_TICKET_RESUME :
        {

            origin=T.origin;

// Resume connection. Try and send early data in GET
            rtn=TLS13_resume(client,hostname,IO,RMS,K_send,K_recv,STS,T,GET);
            if (!rtn)
            {
                mydelay();
                return;
            }

// Send client message again - if it failed to go as early data
            if (rtn!=2)
                client_send(client,&GET,&K_send,&IO);
        }
        break;
    case TLS_FULL_HANDSHAKE :
    default:
        {    
            rtn=TLS13_full(client,hostname,IO,RMS,K_send,K_recv,STS,CPB,cipher_suite,favourite_group); // Do full TLS 1.3 handshake 
            if (!rtn)
            { // failed
                mydelay();
                return;
            }
// Initialise a ticket structure, and remember which cipher suite and which key exchange group was agreed.
            initTicketContext(&T); 
            T.cipher_suite=cipher_suite;
            T.favourite_group=favourite_group;
            origin=TLS_FULL_HANDSHAKE;

// Send client message
            client_send(client,&GET,&K_send,&IO);
        }
    }

// Run the Application - Process server responses
    rtn=processServerMessage(client,&IO,&K_recv,&STS,&T); 
    if (rtn<0)
        sendClientAlert(client,alert_from_cause(rtn),&K_send);
    else
        sendClientAlert(client,CLOSE_NOTIFY,&K_send);

// check if a ticket was received
    if (T.lifetime==0)
    { // no ticket provided
        mydelay();
        return;
    } else {
        recoverPSK(cipher_suite,&RMS,&T.NONCE,&T.PSK); // recover PSK using NONCE and RMS, and store it with ticket
        T.origin=origin;

    }
}

// Try for a full handshake - disconnect - try to resume connection - repeat
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
// Note that the ESP32 does things rather differently...

void setup()
{
    Serial.begin(115200); while (!Serial) ;
// make WiFi connection
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.print("\nWiFi connected with IP: ");
    Serial.println(WiFi.localIP());
             
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Hostname= ",hostname,0,NULL);
#endif

// Initialise Security Abstraction Layer
    bool retn=SAL_initLib();
    if (!retn)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Security Abstraction Layer failed to start\n",NULL,0,NULL);
#endif
        return;
    }

// Client Capabilities to be advertised to Server - obtained from the Security Abstraction Layer (SAL)

    CPB.nsg=SAL_groups(CPB.supportedGroups);    // Get supported Key Exchange Groups in order of preference
    CPB.nsc=SAL_ciphers(CPB.ciphers);           // Get supported Cipher Suits
    CPB.nsa=SAL_sigs(CPB.sigAlgs);              // Get supported TLS1.3 signing algorithms 
    CPB.nsac=SAL_sigCerts(CPB.sigAlgsCert);     // Get supported Certificate signing algorithms 

#ifdef ESP32
    xTaskCreatePinnedToCore(
        myloop
        ,  "client"   // A name just for humans
        ,  32768  // 32K-6K This stack size can be checked & adjusted by reading the Stack Highwater
        ,  NULL
        ,  3  // Priority, with 3 (configMAX_PRIORITIES - 1) being the highest, and 0 being the lowest.
        ,  NULL 
        ,  ARDUINO_RUNNING_CORE);
#endif

}


#ifdef ESP32
void loop()
{
}

void myloop(void *pvParameters) {
    (void) pvParameters;
    while (1)
    {
#else
void loop() {
#endif
    Socket client;
    ticket T;
    initTicketContext(&T);

// make connection using full handshake...
    if (!client.connect(hostname,port))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Unable to access ",hostname,0,NULL);
#endif
        mydelay();
 		return;
    }
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"\nAttempting full handshake\n",NULL,0,NULL);
#endif
    makeConnection(client,TLS_FULL_HANDSHAKE,T);
// drop the connection..
    client.stop();
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Connection closed\n",NULL,0,NULL);
#endif
    delay(5000);


// try to resume connection using...
    if (!client.connect(hostname,port))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Unable to access ",hostname,0,NULL);
#endif
        mydelay();
 		return;
    }
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"\nAttempting resumption\n",NULL,0,NULL);
#endif
    makeConnection(client,TLS_TICKET_RESUME,T);
    client.stop();
// drop the connection..
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Connection closed\n",NULL,0,NULL);
#endif

#ifdef ESP32
    Serial.print("Amount of unused stack memory ");     // useful information!
    Serial.println(uxTaskGetStackHighWaterMark(NULL));
    delay(5000);
    }
#else
    delay(5000);
#endif
}
