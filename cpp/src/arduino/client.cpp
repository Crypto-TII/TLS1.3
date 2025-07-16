// Client side C/C++ program to demonstrate TLS1.3 
// Arduino Version

#include <time.h>

#include "tls_protocol.h"
#include "tls_wifi.h"
#include "tls_logger.h"
// for SAL testing and experimental IBE
#include "tls_sal.h"
#include "tls_bfibe.h"
#include "tls_pqibe.h"

#define STASSID "your-ssid"
#define STAPSK "your-password"

int readLine(char *line) {
  int i=0;
  while (1) {
    if (Serial.available()) {
      char c = Serial.read();

      if (c == '\r') {
        // ignore
        continue;
      } else if (c == '\n') {
        break;
      }
      line[i++] = c;
    }
  }
  line[i]=0;
  return i;
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

void mydelay()
{
    while (1) delay(1000);
}

static void nameGroup(int kex)
{
    switch(kex) {
    case X25519:
        Serial.println("X25519");
        break;
    case SECP256R1:
        Serial.println("SECP256R1");   
        break;
    case SECP384R1:
        Serial.println("SECP384R1");   
        break;
    case MLKEM768:
        Serial.println("MLKEM768");   
        break;
    case HYBRID_KX:
        Serial.println("MLKEM768+X25519");   
        break;
    default:
        Serial.println("Non-standard");   
        break;
    }
}

static void nameCipher(int cipher_suite)
{
    switch (cipher_suite)
    {
    case TLS_AES_128_GCM_SHA256:
		Serial.println("TLS_AES_128_GCM_SHA256");
        break;
    case TLS_AES_256_GCM_SHA384:
        Serial.println("TLS_AES_256_GCM_SHA384");   
        break;
    case TLS_CHACHA20_POLY1305_SHA256:
        Serial.println("TLS_CHACHA20_POLY1305_SHA256");   
        break;
    default:
        Serial.println("Non-standard");   
        break;
    }
}

static void nameSigAlg(int sigAlg)
{
    switch (sigAlg)
    {
    case ECDSA_SECP256R1_SHA256:
        Serial.println("ECDSA_SECP256R1_SHA256");
        break;
    case RSA_PSS_RSAE_SHA256:
        Serial.println("RSA_PSS_RSAE_SHA256");   
        break;
    case RSA_PKCS1_SHA256:
        Serial.println("RSA_PKCS1_SHA256");   
        break;
    case ECDSA_SECP384R1_SHA384:
        Serial.println("ECDSA_SECP384R1_SHA384");
        break;
    case RSA_PSS_RSAE_SHA384:
        Serial.println("RSA_PSS_RSAE_SHA384");   
        break;
    case RSA_PKCS1_SHA384:
        Serial.println("RSA_PKCS1_SHA384");   
        break;
    case RSA_PSS_RSAE_SHA512:
        Serial.println("RSA_PSS_RSAE_SHA512");   
        break;
    case RSA_PKCS1_SHA512:
        Serial.println("RSA_PKCS1_SHA512");   
        break;
    case ED25519:
        Serial.println("ED25519");   
        break;
    case ED448:
        Serial.println("ED448");   
        break;
    case MLDSA44:
        Serial.println("MLDSA44");   
        break;
    case MLDSA65:
        Serial.println("MLDSA65");   
        break;
    case MLDSA44_P256:
        Serial.println("MLDSA44 + P256");   
        break;
    default:
        Serial.println("Non-standard");   
        break;
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

// may need increasing to 80000     
#define STACKSIZE 65536
// define this to experiment with IBE PSK
//#define HAVE_PSK


// This rather strange program structure is required by the Arduino development environment
// A hidden main() functions calls setup() once, and then repeatedly calls loop()
// This actually makes a lot of sense in an embedded environment
// This structure does however mean that a certain of amount of global data is inevitable
// Note that the ESP32 does things rather differently...

void setup()
{
    char* ssid = (char *)STASSID;
    char* password =  (char *)STAPSK;

    Serial.begin(115200); while (!Serial) ;
// make WiFi connection
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.print("\nWiFi connected with IP: ");
    Serial.println(WiFi.localIP());

// Set up time 
  NTP.begin("pool.ntp.org", "time.nist.gov"); // may need to be changed to local time server

  Serial.print("Waiting for NTP time sync: ");
  NTP.waitSet([]() {
    Serial.print(".");
  });
  Serial.println("");

  time_t now = time(nullptr);

  Serial.print("Epoch time in seconds: ");
  Serial.println((long)now);

#ifdef ESP32
    xTaskCreatePinnedToCore(
        myloop
        ,  "client"   // A name just for humans
        ,  STACKSIZE  // This stack size can be checked & adjusted by reading the Stack Highwater
        ,  NULL
        ,  3  // Priority, with 3 (configMAX_PRIORITIES - 1) being the highest, and 0 being the lowest.
        ,  NULL 
        ,  ARDUINO_RUNNING_CORE);
#endif
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

void testTLSconnect(Socket *client,char *hostname,int port)
{
    char get[256];
    octad GET={0,sizeof(get),get};     // initial message
    char resp[40];
    octad RESP={0,sizeof(resp),resp};  // response
    char r32[32];
    octad R32={0,sizeof(r32),r32};
    char myhostname[TLS_MAX_SERVER_NAME];

    int start,elapsed;
    TLS_session state=TLS13_start(client,hostname);
    TLS_session *session=&state;
    log(IO_PROTOCOL,(char *)"\nHostname= ",hostname,0,NULL);

#ifdef HAVE_PSK
        strcpy(myhostname, "localhost"); // for now assume its only for use with localhost
#if CRYPTO_SETTING == TINY_ECC || CRYPTO_SETTING == TYPICAL || CRYPTO_SETTING == EDDSA
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
        session->T.favourite_group=MLKEM768;
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
        session->T.max_early_data=1024;
        session->T.cipher_suite=TLS_AES_128_GCM_SHA256;
        session->T.origin=TLS_EXTERNAL_PSK;
        session->T.valid=true;

#endif

    make_client_message(&GET,hostname);
// make connection using full handshake...
    if (!client->connect(hostname,port))
    {
        log(IO_PROTOCOL,(char *)"Unable to access ",hostname,0,NULL);
        while (Serial.available() == 0) {}
        //Serial.read(); 
 		return;
    }
    int rtn;
    start = millis();
    bool success=TLS13_connect(session,&GET,NULL);  // FULL handshake and connection to server
    if (success) {
        rtn=TLS13_recv(session,&RESP,NULL);    // Server response + ticket
        if (rtn>0) {
            log(IO_APPLICATION,(char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
            TLS13_stop(session);
        }
    }
// drop the link
    TLS13_clean(session);   // but leave ticket intact
    client->stop();
    elapsed = (millis() - start);
    Serial.print("Full TLS connection (ms)= "); Serial.println(elapsed);

    log(IO_PROTOCOL,(char *)"Connection closed\n\n",NULL,0,NULL);
    delay(5000);


// try to resume connection using...
    if (!client->connect(hostname,port))
    {
        log(IO_PROTOCOL,(char *)"Unable to access ",hostname,0,NULL);
        while (Serial.available() == 0) {}
 		return;
    }

    start = millis();
    success=TLS13_connect(session,&GET,NULL);  // Resumption handshake and connection to server
    if (success) {
        rtn=TLS13_recv(session,&RESP,NULL);    // Server response + ticket
        if (rtn>0) {
            log(IO_APPLICATION,(char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
            TLS13_stop(session);
        }
    } else {
        log(IO_APPLICATION,(char *)"Resumption failed (no ticket?) \n",NULL,0,NULL);
    }
   
    client->stop();
    elapsed = (millis() - start);
    Serial.print("Resumed TLS connection (ms)= "); Serial.println(elapsed);
// dropped the connection..
    log(IO_PROTOCOL,(char *)"Connection closed\n",NULL,0,NULL);
    TLS13_end(session);
}

#ifdef ESP32
void loop()
{ // main task loops around here
    delay(1000);
}

void myloop(void *pvParameters) {
    (void) pvParameters;
    while (1)
    {
#else
void loop() {
#endif

    Socket client;
    int i,len,port=443;
    char hostname[128];
    int start,elapsed;

// Initialise Security Abstraction Layer
    bool retn=SAL_initLib();
    if (!retn)
    {
        log(IO_PROTOCOL,(char *)"Security Abstraction Layer failed to start\n",NULL,0,NULL);
        mydelay();
        return;
    }

    Serial.print("Enter URL (e.g. www.bbc.co.uk) = ");
    len=readLine(hostname);
    Serial.println("");
    if (len==0)
    { // print out some information
        int ns,iterations;
        int nt[20];
        Serial.print("\nCryptography by "); Serial.println(SAL_name());
        ns=SAL_groups(nt);
        Serial.println("SAL supported Key Exchange groups");
        for (i=0;i<ns;i++ )
        {
            Serial.print("    ");
            nameGroup(nt[i]);

            char sk[TLS_MAX_KEX_SECRET_KEY_SIZE];
            octad SK={0,sizeof(sk),sk};
            char pk[TLS_MAX_KEX_PUB_KEY_SIZE];
            octad PK={0,sizeof(pk),pk};
            char ss[TLS_MAX_SHARED_SECRET_SIZE];
            octad SS={0,sizeof(ss),ss};

            iterations=0;
            start = millis();
            do {
                SAL_generateKeyPair(nt[i],&SK,&PK);
                iterations++;
                elapsed = (millis() - start);
            } while (elapsed < 1000 || iterations < 4);
            elapsed = elapsed / iterations;
            Serial.print("        Key Generation (ms)= "); Serial.println(elapsed);

            iterations=0;
            start = millis();
            do {
                SAL_generateSharedSecret(nt[i],&SK,&PK,&SS);   
                iterations++;
                elapsed = (millis() - start);
            } while (elapsed < 1000 || iterations < 4);
            elapsed = elapsed / iterations;
            Serial.print("        Shared Secret (ms)= "); Serial.println(elapsed);

        }
        ns=SAL_ciphers(nt);
        Serial.println("SAL supported Cipher suites");
        for (i=0;i<ns;i++ )
        {
            Serial.print("    ");
            nameCipher(nt[i]);
        }
        ns=SAL_sigs(nt);
        Serial.println("SAL supported TLS signatures");
        for (i=0;i<ns;i++ )
        {
            Serial.print("    ");
            nameSigAlg(nt[i]);
        }
        ns=SAL_sigCerts(nt);
        Serial.println("SAL supported Certificate signatures");
        for (i=0;i<ns;i++ )
        {
            Serial.print("    ");
            nameSigAlg(nt[i]);
        }
        while (Serial.available() == 0) {}
        //Serial.read(); 
        return;
    }

// make a connection - get hostname
    bool contains_colon = false;
    len = strlen(hostname);
    for (i=0;i<len;++i)
    {
        if(hostname[i] == ':')
        {
            contains_colon = true;
            break;
        }
    }
    if (contains_colon)
    {
        char port_part[5];
        strncpy(port_part, hostname+sizeof(char)*(i+1), (len - i));
        port = atoi(port_part);
        hostname[i]=0;
    }    
#ifdef ESP32
    int start_stack=STACKSIZE-uxTaskGetStackHighWaterMark(NULL);
    Serial.print("Initial Stack memory used ");     // useful information!
    Serial.println(start_stack);
#endif

    testTLSconnect(&client,hostname,port);

#ifdef ESP32
    Serial.print("Stack memory used ");     // useful information!
    Serial.println(STACKSIZE-uxTaskGetStackHighWaterMark(NULL)-start_stack);
    SAL_endLib();
    delay(5000);
    }
#else
    SAL_endLib();
    delay(5000);
#endif
    while (Serial.available() == 0) {}
    //Serial.read(); 
}
