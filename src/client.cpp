// Client side C/C++ program to demonstrate TLS1.3 
// g++ -O2 -c tls*.cpp
// ar rc tls.a tls_protocol.o tls_keys_calc.o tls_sockets.o tls_cert_chain.o tls_client_recv.o tls_client_send.o tls_tickets.o tls_logger.o tls_cacerts.o tls_crypto_api.o tls_octads.o tls_x509.o
// g++ -O2 client.cpp tls.a core.a -o client

#include "tls_sal.h"
#include "tls_protocol.h"

#ifdef TLS_ARDUINO
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
bool PSKMODE=false;

int port=443;

#ifdef TLS_ARDUINO
char* ssid = "TP-LINK_5B40F0";
char* password =  "********";
char* hostname = "swifttls.org";
void mydelay()
{
    while (1) delay(1000);
}
#else
char hostname[TLS_MAX_SERVER_NAME];
SocketType socketType = SocketType::SOCKET_TYPE_AF_INET;
void mydelay()
{}
#endif

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
#ifdef TLS_ARDUINO
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


// Client Capabilities to be advertised to Server
// Get supported Key Exchange Groups in order of preference
    CPB.nsg=SAL_groups(CPB.supportedGroups);
// Get supported Cipher Suits
    CPB.nsc=SAL_ciphers(CPB.ciphers);
// Get supported TLS1.3 signing algorithms 
    CPB.nsa=SAL_sigs(CPB.sigAlgs);
// Get supported Certificate signing algorithms 
    CPB.nsac=SAL_sigCerts(CPB.sigAlgsCert);

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

// Try for a full handshake - disconnect - try to resume connection - repeat
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
    int rtn,favourite_group,cipher_suite;
    char rms[TLS_MAX_HASH];
    octad RMS = {0,sizeof(rms),rms};   // Resumption master secret
    char sts[TLS_MAX_HASH];
    octad STS = {0,sizeof(sts),sts};   // server traffic secret
    char io[TLS_MAX_IO_SIZE];
    octad IO={0,sizeof(io),io};        // main IO buffer - all messages come and go via this octad   --- BIG
    char get[256];
    octad GET={0,sizeof(get),get};     // initial message
    ticket T;
    crypto K_send, K_recv;             // crypto contexts, sending and receiving

    initCryptoContext(&K_send);
    initCryptoContext(&K_recv);
    make_client_message(&GET,hostname);

#ifndef TLS_ARDUINO
    Socket client = (socketType == SocketType::SOCKET_TYPE_AF_UNIX) ?
                    Socket::UnixSocket():
                    Socket::InetSocket();
#else
    Socket client;
#endif

    if (!client.connect(hostname,port))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Unable to access ",hostname,0,NULL);
#endif
        mydelay();
 		return;
    }

    if (!PSKMODE) // Don't have a preshared Key
    {
    

// Do full TLS 1.3 handshake unless PSK available
        rtn=TLS13_full(client,hostname,IO,RMS,K_send,K_recv,STS,CPB,cipher_suite,favourite_group);
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
        client_send(client,&GET,&K_send,&IO);

// Initialise a ticket structure, and remember which cipher suite and which key exchange group was agreed.
        initTicketContext(&T,cipher_suite,favourite_group);
// Process server responses
        rtn=processServerMessage(client,&IO,&K_recv,&STS,&T); 
        if (rtn<0)
            sendClientAlert(client,alert_from_cause(rtn),&K_send);
        else
            sendClientAlert(client,CLOSE_NOTIFY,&K_send);
        client.stop();
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Connection closed\n",NULL,0,NULL);
#endif


//printf("Press Enter to Continue");
//while( getchar() != '\n' );


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

    } else {
// we have a pre-shared key..!
// Test with openssl s_server -tls1_3 -verify 0 -cipher PSK-AES128-GCM-SHA256 -psk_identity 42 -psk 0102030405060708090a0b0c0d0e0f10 -nocert -max_send_frag 4096 -accept 4433 -www  

#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"\nAttempting connection with PSK\n",NULL,0,NULL);
#endif

        char psk[TLS_MAX_KEY];
        octad PSK = {0,sizeof(psk),psk};    // Pre-Shared Key   
        char psk_label[32];
        octad PSK_LABEL={0,sizeof(psk_label),psk_label};

        PSK.len=16;
        for (int i=0;i<16;i++)
            PSK.val[i]=i+1;                // Fake a 128-bit pre-shared key
        PSK_LABEL.len=2;
        PSK_LABEL.val[0]='4';              // Fake a pre-shared key label
        PSK_LABEL.val[1]='2'; 

        initTicketContext(&T,TLS_AES_128_GCM_SHA256,CPB.supportedGroups[0]);  // Create a special Ticket for PSK
        OCT_copy(&T.TICK,&PSK_LABEL);
        OCT_copy(&T.NONCE,&PSK);
        T.max_early_data=1024;
    }

#ifdef TLS_ARDUINO
// clear out the socket RX buffer
    clearsoc(client,&IO);
#endif

// Resume connection. Try and send early data in GET
    rtn=TLS13_resume(client,hostname,IO,RMS,K_send,K_recv,STS,T,GET);
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
        client_send(client,&GET,&K_send,&IO);

// Process server responses
    rtn=processServerMessage(client,&IO,&K_recv,&STS,&T); 
    if (rtn<0)
        sendClientAlert(client,alert_from_cause(rtn),&K_send);
    else
        sendClientAlert(client,CLOSE_NOTIFY,&K_send);
    client.stop();  // exit and close session

#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Connection closed\n",NULL,0,NULL);
#endif
#ifdef ESP32
    Serial.print("Amount of unused stack memory ");
    Serial.println(uxTaskGetStackHighWaterMark( NULL ));
    delay(5000);
}
#endif

#ifdef TLS_ARDUINO
    delay(5000);
#endif
}

#ifndef TLS_ARDUINO
int main(int argc, char const *argv[])
{
    argv++; argc--;
    socketType = SocketType::SOCKET_TYPE_AF_INET;

    if (argc==1 && strcmp(argv[0],"psk")==0)
    {
        printf("PSK mode selected\n");
        argc=0;
        PSKMODE=true;
    }

    if(argc==0)
    {
// testing against openssl s_server -tls1_3 -key ***.pem -cert ****.pem -accept 4433 -www
        strcpy(hostname, "localhost");
        port = 4433;
    } else if (argc == 1) {
        int i;
        bool contains_colon = false;
        size_t argv0_len = strlen(argv[0]);
        for(i=0; i < argv0_len; ++i)
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
    setup();
    loop();  // just once
}
#endif
