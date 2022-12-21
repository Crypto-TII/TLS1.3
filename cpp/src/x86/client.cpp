// Client side C++ program to demonstrate TLS1.3 
// Linux version
// ./client www.bbc.co.uk

#include <time.h>
#include "tls_sal.h"
#include "tls_protocol.h"
#include "tls_bfibe.h"
#include "tls_pqibe.h"

#define MIN_TIME 1.0
#define MIN_ITERS 1000

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

//printf("PSK.len= %d\n",session->T.PSK.len);
//printf("YYY Lifetime= %x\n",session->T.lifetime);

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

//printf("XXX Lifetime= %x\n",session->T.lifetime);

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
    printf("    -r <hostname> remove stored ticket and connect to hostname\n");
    printf("    -s show SAL capabilities\n");
	printf("    -i try IBE connection\n");
    printf("Example:- client www.bbc.co.uk\n");
}

static void nameGroup(int kex)
{
    switch(kex) {
    case X25519:
        printf("X25519\n");
        break;
    case SECP256R1:
        printf("SECP256R1\n");   
        break;
    case SECP384R1:
        printf("SECP384R1\n");   
        break;
    case KYBER768:
        printf("KYBER768\n");   
        break;
    case HYBRID_KX:
        printf("KYBER768+X25519\n");   
        break;
    default:
        printf("Non-standard\n");   
        break;
    }
}

static void nameCipher(int cipher_suite)
{
    switch (cipher_suite)
    {
    case TLS_AES_128_GCM_SHA256:
		printf("TLS_AES_128_GCM_SHA256\n");
        break;
    case TLS_AES_256_GCM_SHA384:
        printf("TLS_AES_256_GCM_SHA384\n");   
        break;
    case TLS_CHACHA20_POLY1305_SHA256:
        printf("TLS_CHACHA20_POLY1305_SHA256\n");   
        break;
    default:
        printf("Non-standard\n");   
        break;
    }
}

static void nameSigAlg(int sigAlg)
{
    switch (sigAlg)
    {
    case ECDSA_SECP256R1_SHA256:
        printf("ECDSA_SECP256R1_SHA256\n");
        break;
    case RSA_PSS_RSAE_SHA256:
        printf("RSA_PSS_RSAE_SHA256\n");   
        break;
    case RSA_PKCS1_SHA256:
        printf("RSA_PKCS1_SHA256\n");   
        break;
    case ECDSA_SECP384R1_SHA384:
        printf("ECDSA_SECP384R1_SHA384\n");
        break;
    case RSA_PSS_RSAE_SHA384:
        printf("RSA_PSS_RSAE_SHA384\n");   
        break;
    case RSA_PKCS1_SHA384:
        printf("RSA_PKCS1_SHA384\n");   
        break;
    case RSA_PSS_RSAE_SHA512:
        printf("RSA_PSS_RSAE_SHA512\n");   
        break;
    case RSA_PKCS1_SHA512:
        printf("RSA_PKCS1_SHA512\n");   
        break;
    case ED25519:
        printf("ED25519\n");   
        break;
    case DILITHIUM2:
        printf("DILITHIUM2\n");   
        break;
    case DILITHIUM3:
        printf("DILITHIUM3\n");   
        break;
    case DILITHIUM2_P256:
        printf("DILITHIUM2 + P256\n");   
        break;
    default:
        printf("Non-standard\n");   
        break;
    }
}


// convert TLS octad to MIRACL core octet
static octet octad_to_octet(octad *x)
{
    octet y;
    if (x!=NULL) {
        y.len=x->len;
        y.max=x->max;
        y.val=x->val;
    } else {
        y.len=y.max=0;
        y.val=NULL;
    }
    return y;
}

//extern int BYTES_READ;
//extern int BYTES_WRITTEN;

int main(int argc, char const *argv[])
{
    char get[256];
    octad GET={0,sizeof(get),get};     // initial message
    char resp[40];
    octad RESP={0,sizeof(resp),resp};  // response (will be truncated)
    char hostname[TLS_MAX_SERVER_NAME];
    char myhostname[TLS_MAX_SERVER_NAME];
    char psk[TLS_MAX_KEY];
    octad PSK = {0,sizeof(psk),psk};    // Pre-Shared Key   
    char psk_label[32];
    octad PSK_label={0,sizeof(psk_label),psk_label};
    char r32[32];
    octad R32={0,sizeof(r32),r32};
    bool HAVE_PSK=false;
    bool HAVE_TICKET=false;
    bool TICKET_FAILED=false;

    int psk_type=PSK_NOT;

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
        log(IO_PROTOCOL,(char *)"Security Abstraction Layer failed to start\n",NULL,0,NULL);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[ip],"-p")==0)
    {
        if (ip<argc)
        {
            printf("PSK mode selected - have a shared key\n");
            ip++;
 
            psk_type=PSK_KEY;

            OCT_append_string(&PSK_label,(char *)argv[1]);
            PSK.len=16;
            for (int i=0;i<16;i++)
                PSK.val[i]=i+1;                // Fake a 128-bit pre-shared key
            HAVE_PSK=true;
        }
    }

    else if (strcmp(argv[ip],"-i")==0)
    {
        if (ip<argc)
        {
            printf("PSK mode selected\n");
            ip++;
            psk_type=PSK_IBE;
            HAVE_PSK=true;
        }
    }

    else if (strcmp(argv[ip],"-r")==0)
    {
        printf("Ticket removed\n");
        removeTicket(); ip++;
		if (ip>=argc) exit(0);
        //exit(0);
    }

    else if (strcmp(argv[ip],"-s")==0)
    { // interrogate SAL
        int i,ns,iterations;
        int nt[20];
        clock_t start;
        double elapsed;
        printf("Cryptography by %s\n",SAL_name());
        ns=SAL_groups(nt);
        printf("SAL supported Key Exchange groups\n");
        for (i=0;i<ns;i++ )
        {
            printf("    ");
            nameGroup(nt[i]);

            char sk[TLS_MAX_KEX_SECRET_KEY_SIZE];
            octad SK={0,sizeof(sk),sk};
            char pk[TLS_MAX_KEX_PUB_KEY_SIZE];
            octad PK={0,sizeof(pk),pk};

            iterations=0;
            start = clock();
            do {
                SAL_generateKeyPair(nt[i],&SK,&PK);
                iterations++;
                elapsed = (clock() - start) / (double)CLOCKS_PER_SEC;
            } while (elapsed < MIN_TIME || iterations < MIN_ITERS);
            elapsed = 1000.0 * elapsed / iterations;
            printf("        Key Generation %8.2lf ms\n", elapsed);
        }
        ns=SAL_ciphers(nt);
        printf("SAL supported Cipher suites\n");
        for (i=0;i<ns;i++ )
        {
            printf("    ");
            nameCipher(nt[i]);
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
            hostname[i]=0;
            char port_part[5];
            strncpy(port_part, argv[ip]+sizeof(char)*(i+1), (argv_len - i));
            port = atoi(port_part);

            //char ipaddr[20];
            //getIPaddress(ipaddr,hostname);
            //printf("ip address= %s\n",ipaddr);
        } else {
            strcpy(hostname, argv[ip]);
            port = 443;
        }
    }
    log(IO_PROTOCOL,(char *)"Hostname= ",hostname,0,NULL);

    make_client_message(&GET,hostname);

    if (ip>=argc)
    {
        bad_input();
        exit(EXIT_FAILURE);
    }

    if (!client.connect(hostname,port))
    {
        log(IO_PROTOCOL,(char *)"Unable to access ",hostname,0,NULL);
 		exit(EXIT_FAILURE);
    }

// create new session
    TLS_session state=TLS13_start(&client,hostname);
    TLS_session *session=&state;

    HAVE_TICKET=true;
    if (HAVE_PSK)
    {
        strcpy(myhostname, "localhost"); // for now assume its only for use with localhost
        if (psk_type==PSK_KEY)
        {
            OCT_copy(&session->T.TICK,&PSK_label);      // Insert a special ticket into session 
            OCT_copy(&session->T.PSK,&PSK);
            session->T.favourite_group=X25519;
        }
        if (psk_type==PSK_IBE)
        {
#if CRYPTO_SETTING == TINY_ECC || CRYPTO_SETTING == TYPICAL
            log(IO_PROTOCOL,(char *)"Using Pairing-Based IBE\n",NULL,0,NULL);
            SAL_randomOctad(32,&R32);
            octet MC_R32=octad_to_octet(&R32);
            octet MC_PSK=octad_to_octet(&session->T.PSK);
            octet MC_TICK=octad_to_octet(&session->T.TICK);
            BFIBE_CCA_ENCRYPT(myhostname,&MC_R32,&MC_PSK,&MC_TICK);
            session->T.PSK.len=MC_PSK.len;
            session->T.TICK.len=MC_TICK.len;
            session->T.favourite_group=X25519;
#endif
#if CRYPTO_SETTING == POST_QUANTUM
            log(IO_PROTOCOL,(char *)"Using Post Quantum IBE\n",NULL,0,NULL);
            SAL_randomOctad(32,&R32);
            octet MC_R32=octad_to_octet(&R32);
            octet MC_PSK=octad_to_octet(&session->T.PSK);
            octet MC_TICK=octad_to_octet(&session->T.TICK);
            PQIBE_CCA_ENCRYPT(myhostname,&MC_R32,&MC_PSK,&MC_TICK);
            session->T.PSK.len=MC_PSK.len;
            session->T.TICK.len=MC_TICK.len;
            session->T.favourite_group=KYBER768;
#endif
#if CRYPTO_SETTING == HYBRID
            log(IO_PROTOCOL,(char *)"Using Hybrid Pairing based/Post Quantum IBE\n",NULL,0,NULL);
            char psk2[32];
            octad PSK2={0,sizeof(psk2),psk2};
            char tick2[256];
            octad TICK2={0,sizeof(tick2),tick2};

            SAL_randomOctad(32,&R32);
            octet MC_R32=octad_to_octet(&R32);
            octet MC_PSK=octad_to_octet(&session->T.PSK);
            octet MC_TICK=octad_to_octet(&session->T.TICK);
            PQIBE_CCA_ENCRYPT(myhostname,&MC_R32,&MC_PSK,&MC_TICK);
            session->T.PSK.len=MC_PSK.len;
            session->T.TICK.len=MC_TICK.len;

            SAL_randomOctad(32,&R32);
            MC_PSK=octad_to_octet(&PSK2);
            MC_TICK=octad_to_octet(&TICK2);
            BFIBE_CCA_ENCRYPT(myhostname,&MC_R32,&MC_PSK,&MC_TICK);
            PSK2.len=MC_PSK.len;
            TICK2.len=MC_TICK.len;

            OCT_append_octad(&session->T.PSK,&PSK2);
            OCT_append_octad(&session->T.TICK,&TICK2);
            session->T.favourite_group=HYBRID_KX;
#endif
        }
        session->T.max_early_data=1024;
        session->T.cipher_suite=TLS_AES_128_GCM_SHA256;
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
            TLS13_stop(session);
            client.stop();  // reconnect
            client.connect(hostname,port);
            if (!TLS13_connect(session,&GET)) // try again, this time fall back to a FULL handshake
            {  
				log(IO_APPLICATION,(char *)"TLS Handshake failed\n",NULL,0,NULL);
                TLS13_stop(session);
				TLS13_end(session);
                client.stop();
                return 0;
            }
        } else {
			log(IO_APPLICATION,(char *)"TLS Handshake failed\n",NULL,0,NULL);
            TLS13_stop(session);
			TLS13_end(session);
            client.stop();
            return 0;
        }
    }
    
//printf("BYTES_READ= %d BYTES_WRITTEN= %d\n",BYTES_READ,BYTES_WRITTEN);

    int rtn=0;
// Get server response, may attach resumption ticket to session
	if (port==443)
	{ // its a regular website. Wait for some HTML from website, then send an alert to close it
		rtn=TLS13_recv(session,&RESP);
		if (rtn==APPLICATION) {
			log(IO_APPLICATION,(char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
            TLS13_stop(session);
        }
	}
	if (port==4433)
	{ // Wait for Server to end it with a close notify alert
        
		for (; ; )
		{
			rtn=TLS13_recv(session,&RESP);
			if (rtn<0 || rtn==TIMED_OUT)
			{ // Either problem on my side, or I got an alert
				break;
			}
			if (rtn==APPLICATION)
				log(IO_APPLICATION,(char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
		}
	}
    if (rtn==CLOSURE_ALERT_RECEIVED) {
        TLS13_stop(session);
    }
// If session collected a Ticket, store it somewhere for next time
    if (session->T.valid && !TICKET_FAILED)
        storeTicket(session);

    TLS13_end(session);
    client.stop();
    return 0;
}
