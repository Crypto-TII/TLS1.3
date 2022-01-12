// Client side C++ program to demonstrate TLS1.3 
// Linux version
// ./client www.bbc.co.uk

#include "tls_sal.h"
#include "tls_protocol.h"

// Extract ticket from cookie file, and attach to session
static void storeTicket(TLS_session *session)
{
    FILE *fp;
    fp=fopen("cookie.txt","wt");
    char line[2050];
    fprintf(fp,"%s\n",session->hostname);
    OCT_output_hex(&session->T.TICK,2048,line);
    fprintf(fp,"%s\n",line);
    OCT_output_hex(&session->T.PSK,2048,line);
    fprintf(fp,"%s\n",line);
    fprintf(fp,"%x\n",session->T.age_obfuscator); 
    fprintf(fp,"%x\n",session->T.max_early_data);
    fprintf(fp,"%x\n",session->T.birth);
    fprintf(fp,"%x\n",session->T.lifetime);
    fprintf(fp,"%x\n",session->T.cipher_suite);
    fprintf(fp,"%x\n",session->T.favourite_group);
    fprintf(fp,"%x\n",session->T.origin);
    fclose(fp);
}

// restore ticket into session from cookie file
static bool recoverTicket(TLS_session *session)
{
    FILE *fp;
    char line[2050];
    initTicketContext(&session->T); 

    fp=fopen("cookie.txt","rt");
    if (fp==NULL)
        return false;  
    
    if (fscanf(fp,"%s\n",line)) {};

    if (strcmp(line,session->hostname)!=0)  // Is it a ticket for this host?
        return false;

    if (fscanf(fp,"%s\n",line)) {};
    OCT_from_hex(&session->T.TICK,line);
    if (fscanf(fp,"%s\n",line)) {};
    OCT_from_hex(&session->T.PSK,line);
    if (fscanf(fp,"%x",&session->T.age_obfuscator)) {};
    if (fscanf(fp,"%x",&session->T.max_early_data)) {};
    if (fscanf(fp,"%x",&session->T.birth)) {};
    if (fscanf(fp,"%x",&session->T.lifetime)) {};
    if (fscanf(fp,"%x",&session->T.cipher_suite)) {};
    if (fscanf(fp,"%x",&session->T.favourite_group)) {};
    if (fscanf(fp,"%x",&session->T.origin)) {};
    fclose(fp);
    session->T.valid=true;
    return true;
}

static void removeTicket()
{
    remove("cookie.txt");
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

enum SocketType{
    SOCKET_TYPE_AF_UNIX,
    SOCKET_TYPE_AF_INET
};

static void bad_input()
{
    printf("Incorrect Usage\n");
    printf("client <flags> <hostname>\n");
    printf("client <flags> <hostname:port>\n");
    printf("(hostname may be localhost)\n");
    printf("(port defaults to 443, or 4433 on localhost)\n");
    printf("Resumption automatically attempted if recent ticket found\n");
    printf("Valid flags:- \n");
    printf("    -p <n> hostname (where <n> is preshared key identity)\n");
    printf("    -r remove stored ticket\n");
    printf("    -s show SAL capabilities\n");
    printf("Example:- client www.bbc.co.uk\n");
}

int main(int argc, char const *argv[])
{
    char get[256];
    octad GET={0,sizeof(get),get};     // initial message
    char resp[40];
    octad RESP={0,sizeof(resp),resp};  // response (will be truncated)
    char hostname[TLS_MAX_SERVER_NAME];
    char psk[TLS_MAX_KEY];
    octad PSK = {0,sizeof(psk),psk};    // Pre-Shared Key   
    char psk_label[32];
    octad PSK_label={0,sizeof(psk_label),psk_label};
    bool HAVE_PSK=false;
    bool HAVE_TICKET=false;
    bool TICKET_FAILED=false;
    int port=443;
    SocketType socketType = SocketType::SOCKET_TYPE_AF_INET;
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

// Initialise Security Abstraction Layer
    bool retn=SAL_initLib();
    if (!retn)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Security Abstraction Layer failed to start\n",NULL,0,NULL);
#endif
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[ip],"-p")==0)
    {
        ip++;
        if (ip<argc)
        {
            printf("PSK mode selected\n");
            ip++;
 
            OCT_append_string(&PSK_label,(char *)argv[1]);
            PSK.len=16;
            for (int i=0;i<16;i++)
                PSK.val[i]=i+1;                // Fake a 128-bit pre-shared key
            HAVE_PSK=true;
        }
    }

    if (strcmp(argv[ip],"-r")==0)
    {
        printf("Ticket removed\n");
        removeTicket();
        exit(0);
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

    make_client_message(&GET,hostname);

    if (ip>=argc)
    {
        bad_input();
        exit(EXIT_FAILURE);
    }

    if (!client.connect(hostname,port))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Unable to access ",hostname,0,NULL);
#endif
 		exit(EXIT_FAILURE);
    }

// create new session
    TLS_session state=TLS13_start(&client,hostname);
    TLS_session *session=&state;

    HAVE_TICKET=true;
    if (HAVE_PSK)
    {
        OCT_copy(&session->T.TICK,&PSK_label);      // Insert a special ticket into session 
        OCT_copy(&session->T.PSK,&PSK);
        session->T.max_early_data=1024;
        session->T.cipher_suite=TLS_AES_128_GCM_SHA256;
        session->T.favourite_group=session->CPB.supportedGroups[0];
        session->T.origin=TLS_EXTERNAL_PSK;
        session->T.valid=true;
        removeTicket();  // delete any stored ticket - fall into resumption mode
    } else {
        if (!recoverTicket(session))
            HAVE_TICKET=false;
    }
//    removeTicket();    // old tickets MAY be re-used, so don't remove

// Make TLS connection, and try to send early data. 
// If early data not allowed, early data will still be sent internally after handshake completes
 
    if (!TLS13_connect(session,&GET))
    { 
        if (HAVE_TICKET)
        { // ticket didn't work !?
            TICKET_FAILED=true;
            removeTicket();
            client.stop();  // reconnect
            client.connect(hostname,port);
            if (!TLS13_connect(session,&GET)) // try again, this time fall back to a FULL handshake
            {  
#if VERBOSITY >= IO_APPLICATION
        logger((char *)"TLS Handshake failed\n",NULL,0,NULL);
#endif
                exit(EXIT_FAILURE);
            }
        } else {
#if VERBOSITY >= IO_APPLICATION
        logger((char *)"TLS Handshake failed\n",NULL,0,NULL);
#endif
            exit(EXIT_FAILURE);
        }
    }

// Get server response, may attach resumption ticket to session
    int rtn=TLS13_recv(session,&RESP);

#if VERBOSITY >= IO_APPLICATION
    logger((char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
#endif

    if (rtn<0)
        sendClientAlert(session,alert_from_cause(rtn));
    else
        sendClientAlert(session,CLOSE_NOTIFY);

// If session collected a Ticket, store it somewhere for next time
    if (session->T.valid && !TICKET_FAILED)
        storeTicket(session);

    TLS13_end(session);
    return 0;
}
