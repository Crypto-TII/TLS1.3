// Client side C/C++ program to demonstrate TLS1.3 
// Arduino Version

#include "tls_sal.h"
#include "tls_protocol.h"
#include "tls_wifi.h"

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
    case KYBER768:
        Serial.println("KYBER768");   
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
    case DILITHIUM3:
        Serial.println("DILITHIUM3\n");   
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

// This rather strange program structure is required by the Arduino development environment
// A hidden main() functions calls setup() once, and then repeatedly calls loop()
// This actually makes a lot of sense in an embedded environment
// This structure does however mean that a certain of amount of global data is inevitable
// Note that the ESP32 does things rather differently...

void setup()
{
    char* ssid = (char *)"eir79562322-2.4G";
    char* password =  (char *)"********";
//    char* ssid = (char *)"TP-LINK_5B40F0";
//    char* password =  (char *)"********";
    Serial.begin(115200); while (!Serial) ;
// make WiFi connection
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.print("\nWiFi connected with IP: ");
    Serial.println(WiFi.localIP());

#ifdef ESP32
    xTaskCreatePinnedToCore(
        myloop
        ,  "client"   // A name just for humans
        ,  65536  // This stack size can be checked & adjusted by reading the Stack Highwater
        ,  NULL
        ,  3  // Priority, with 3 (configMAX_PRIORITIES - 1) being the highest, and 0 being the lowest.
        ,  NULL 
        ,  ARDUINO_RUNNING_CORE);
#endif

}

#ifdef ESP32
void loop()
{ // main task loops around here
    delay(1000);
}

void myloop(void *pvParameters) {
    (void) pvParameters;
    TLS_session state;
    TLS_session *session=&state;
    while (1)
    {
#else
void loop() {
    TLS_session state;
    TLS_session *session=&state;
#endif
    char get[256];
    octad GET={0,sizeof(get),get};     // initial message
    char resp[40];
    octad RESP={0,sizeof(resp),resp};  // response
    Socket client;
    int i,len,port=443;
    char hostname[128];

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

    if (len==0)
    {
        int ns,iterations;
        int nt[20];
        int start,elapsed;
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
        Serial.read(); 
        return;
    }

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

    state=TLS13_start(&client,hostname);
    log(IO_PROTOCOL,(char *)"\nHostname= ",hostname,0,NULL);

    make_client_message(&GET,hostname);

// make connection using full handshake...
    if (!client.connect(hostname,port))
    {
        log(IO_PROTOCOL,(char *)"Unable to access ",hostname,0,NULL);
        while (Serial.available() == 0) {}
        Serial.read(); 
 		return;
    }

    start = millis();
    bool success=TLS13_connect(session,&GET);  // FULL handshake and connection to server
    if (success) {
        TLS13_recv(session,&RESP);    // Server response + ticket
        if (RESP.len>0)
            log(IO_APPLICATION,(char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
        TLS13_clean(session);   // but leave ticket intact
    }
// drop the connection..
    client.stop();
    elapsed = (millis() - start);
    Serial.print("Full TLS connection (ms)= "); Serial.println(elapsed);

    log(IO_PROTOCOL,(char *)"Connection closed\n\n",NULL,0,NULL);
    delay(5000);

// try to resume connection using...
    if (!client.connect(hostname,port))
    {
        log(IO_PROTOCOL,(char *)"Unable to access ",hostname,0,NULL);
        while (Serial.available() == 0) {}
        Serial.read(); 
 		return;
    }

    start = millis();
    success=TLS13_connect(session,&GET);  // Resumption handshake and connection to server
    if (success) {
        TLS13_recv(session,&RESP);    // Server response + ticket
        log(IO_APPLICATION,(char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
    } else {
        log(IO_APPLICATION,(char *)"Resumption failed (no ticket?) \n",NULL,0,NULL);
    }
    client.stop();
    elapsed = (millis() - start);
    Serial.print("Resumed TLS connection (ms)= "); Serial.println(elapsed);
// dropped the connection..
    log(IO_PROTOCOL,(char *)"Connection closed\n",NULL,0,NULL);

#ifdef ESP32
    Serial.print("Amount of unused stack memory ");     // useful information!
    Serial.println(uxTaskGetStackHighWaterMark(NULL));
    SAL_endLib();
    delay(5000);
    }
#else
    SAL_endLib();
    delay(5000);
#endif
    TLS13_end(session);
    while (Serial.available() == 0) {}
    Serial.read(); 
}
