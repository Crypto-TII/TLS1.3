// Client side C++ program to demonstrate TLS1.3 
// Linux version
// ./client www.bbc.co.uk

#include "tls_sal.h"
#include "tls_protocol.h"

// Output ticket to cookie file
static void storeTicket(ticket *T)
{
    FILE *fp;
    fp=fopen("cookie.txt","wt");
    char line[2050];
    OCT_output_hex(&T->TICK,2048,line);
    fprintf(fp,"%s\n",line);
    OCT_output_hex(&T->PSK,2048,line);
    fprintf(fp,"%s\n",line);
    fprintf(fp,"%x\n",T->age_obfuscator); 
    fprintf(fp,"%x\n",T->max_early_data);
    fprintf(fp,"%x\n",T->birth);
    fprintf(fp,"%x\n",T->lifetime);
    fprintf(fp,"%x\n",T->cipher_suite);
    fprintf(fp,"%x\n",T->favourite_group);
    fprintf(fp,"%x\n",T->origin);
    fclose(fp);
}

static bool recoverTicket(ticket *T)
{
    FILE *fp;
    char line[2050];
    initTicketContext(T); 

    fp=fopen("cookie.txt","rt");
    if (fp==NULL)
        return false;  
    
    if (fscanf(fp,"%s\n",line)) {};
    OCT_from_hex(&T->TICK,line);
    if (fscanf(fp,"%s\n",line)) {};
    OCT_from_hex(&T->PSK,line);
    if (fscanf(fp,"%x",&T->age_obfuscator)) {};
    if (fscanf(fp,"%x",&T->max_early_data)) {};
    if (fscanf(fp,"%x",&T->birth)) {};
    if (fscanf(fp,"%x",&T->lifetime)) {};
    if (fscanf(fp,"%x",&T->cipher_suite)) {};
    if (fscanf(fp,"%x",&T->favourite_group)) {};
    if (fscanf(fp,"%x",&T->origin)) {};
    fclose(fp);
    return true;
}

static void removeTicket()
{
    remove("cookie.txt");
}

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

enum SocketType{
    SOCKET_TYPE_AF_UNIX,
    SOCKET_TYPE_AF_INET
};
char hostname[TLS_MAX_SERVER_NAME];
char psk_label[32];
SocketType socketType = SocketType::SOCKET_TYPE_AF_INET;
void mydelay()
{}

// make connection, using full handshake, resumption, or PSK.
// Full handshake may provide a ticket, stored in file cookie.txt
// Resumption mode consumes a ticket, and may provide one
// If TLS_ARDUINO, just maintain last ticket in memory, and perform immediate resumption
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

    switch (mode)
    {

    case TLS_EXTERNAL_PSK :  // we have a pre-shared key..!    
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"\nAttempting connection with PSK\n",NULL,0,NULL);
#endif
            char psk[TLS_MAX_KEY];
            octad PSK = {0,sizeof(psk),psk};    // Pre-Shared Key   
            octad PSK_LABEL={(int)strlen(psk_label),sizeof(psk_label),psk_label};

            PSK.len=16;
            for (int i=0;i<16;i++)
                PSK.val[i]=i+1;                // Fake a 128-bit pre-shared key

            OCT_copy(&T.TICK,&PSK_LABEL);      // Create a special ticket 
            OCT_copy(&T.PSK,&PSK);
            T.max_early_data=1024;
            T.cipher_suite=TLS_AES_128_GCM_SHA256;
            T.favourite_group=CPB.supportedGroups[0];
            T.origin=TLS_EXTERNAL_PSK;
            removeTicket();  // delete any stored ticket - fall into resumption mode
            HAVE_PSK=true;
        }

    case TLS_TICKET_RESUME :
        {

            if (!HAVE_PSK)
            { 
                if (!recoverTicket(&T))
                {
#if VERBOSITY >= IO_PROTOCOL
                    logger((char *)"No Ticket available - unable to resume\n",NULL,0,NULL);
#endif
                    return;
                }
            }

            origin=T.origin;
            removeTicket();

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
            removeTicket();  // get rid of any unused ticket
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
        removeTicket();  // delete any old ticket

        mydelay();
        return;
    } else {
        recoverPSK(cipher_suite,&RMS,&T.NONCE,&T.PSK); // recover PSK using NONCE and RMS, and store it with ticket
        T.origin=origin;
        storeTicket(&T);
    }
}

// printf's allowed in here
static void bad_input()
{
    printf("Incorrect Usage\n");
    printf("client <flags> <hostname>\n");
    printf("client <flags> <hostname:port>\n");
    printf("(hostname may be localhost)\n");
    printf("(port defaults to 443, or 4433 on localhost)\n");
    printf("Valid flags:- \n");
    printf("    -p <n> hostname (where <n> is preshared key identity)\n");
    printf("    -r hostname (attempt resumption using stored ticket)\n");
    printf("    -s show SAL capabilities\n");
    printf("Example:- client www.bbc.co.uk\n");
    printf("          client -r www.bbc.co.uk\n");
}

int main(int argc, char const *argv[])
{
    Socket client = (socketType == SocketType::SOCKET_TYPE_AF_UNIX) ?
                    Socket::UnixSocket():
                    Socket::InetSocket();
    argv++; argc--;
    int ip=0;

    if (ip>=argc)
    {
        bad_input();
        exit(EXIT_FAILURE);
    }

    int CONNECTION_MODE=TLS_FULL_HANDSHAKE;
    ticket T;
    initTicketContext(&T);

    if (strcmp(argv[ip],"-r")==0)
    {
        ip++;
        if (ip<argc)
        {
            printf("Attempting resumption\n");
            CONNECTION_MODE=TLS_TICKET_RESUME;
        }
    }

    if (strcmp(argv[ip],"-p")==0)
    {
        ip++;
        if (ip<argc)
        {
            printf("PSK mode selected\n");
            strcpy(psk_label,argv[1]);
            ip++;
            CONNECTION_MODE=TLS_EXTERNAL_PSK;
        }
    }

    if (strcmp(argv[ip],"-s")==0)
    { // interrogate SAL
        int i,ns;
        int nt[20];
        printf("Cryptography by %s\n",SAL_name());
        ns=SAL_groups(nt);
        printf("SAL supported Key Exchange groups\n");
        for (i=0;i<ns;i++ )
        {
            printf("    ");
            nameKeyExchange(nt[i]);
        }
        ns=SAL_ciphers(nt);
        printf("SAL supported Cipher suites\n");
        for (i=0;i<ns;i++ )
        {
            printf("    ");
            nameCipherSuite(nt[i]);
        }
        ns=SAL_sigs(nt);
        printf("SAL supported TLS signatures\n");
        for (i=0;i<ns;i++ )
        {
            printf("    ");
            nameSigAlg(nt[i]);
        }
        ns=SAL_sigCerts(nt);
        printf("SAL supported Certificate signatures\n");
        for (i=0;i<ns;i++ )
        {
            printf("    ");
            nameSigAlg(nt[i]);
        }
        exit(0);
    }

    if (ip>=argc)
    {
        bad_input();
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[ip],"localhost")==0)
    {
        strcpy(hostname, "localhost");
        port = 4433;
    } else {
        int i;
        bool contains_colon = false;
        size_t argv_len = strlen(argv[ip]);
        for(i=0; i < argv_len; ++i)
        {
            if(argv[ip][i] == ':')
            {
                contains_colon = true;
                break;
            }
        }
        if (contains_colon)
        {
            strncpy(hostname, argv[ip], i);
            char port_part[5];
            strncpy(port_part, argv[ip]+sizeof(char)*(i+1), (argv_len - i));
            port = atoi(port_part);
        } else {
            strcpy(hostname, argv[ip]);
            port = 443;
        }
    }

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
        exit(EXIT_FAILURE);
    }

// Client Capabilities to be advertised to Server - obtained from the Security Abstraction Layer (SAL)

    CPB.nsg=SAL_groups(CPB.supportedGroups);    // Get supported Key Exchange Groups in order of preference
    CPB.nsc=SAL_ciphers(CPB.ciphers);           // Get supported Cipher Suits
    CPB.nsa=SAL_sigs(CPB.sigAlgs);              // Get supported TLS1.3 signing algorithms 
    CPB.nsac=SAL_sigCerts(CPB.sigAlgsCert);     // Get supported Certificate signing algorithms 

    if (!client.connect(hostname,port))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Unable to access ",hostname,0,NULL);
#endif
        mydelay();
 		exit(EXIT_FAILURE);
    }

    switch (CONNECTION_MODE)
    {
    case TLS_EXTERNAL_PSK :
        makeConnection(client,TLS_EXTERNAL_PSK,T);
        break;
    case TLS_TICKET_RESUME :
        makeConnection(client,TLS_TICKET_RESUME,T);
        break;
    case TLS_FULL_HANDSHAKE :
    default:
        makeConnection(client,TLS_FULL_HANDSHAKE,T);
        break;
    }

    client.stop();

#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Connection closed\n",NULL,0,NULL);
#endif
}
