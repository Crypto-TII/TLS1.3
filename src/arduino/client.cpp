// Client side C/C++ program to demonstrate TLS1.3 
// Arduino Version

#include "tls_sal.h"
#include "tls_protocol.h"
#include "tls_wifi.h"

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
    Serial.begin(115200); while (!Serial) ;
// make WiFi connection
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.print("\nWiFi connected with IP: ");
    Serial.println(WiFi.localIP());

// Initialise Security Abstraction Layer
    bool retn=SAL_initLib();
    if (!retn)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Security Abstraction Layer failed to start\n",NULL,0,NULL);
#endif
        return;
    }

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
    char get[256];
    octad GET={0,sizeof(get),get};     // initial message
    char resp[40];
    octad RESP={0,sizeof(resp),resp};  // response
    Socket client;
    int port=443;
    char* hostname = (char *)"www.bbc.co.uk";  // HTTPS TLS1.3 server
    TLS_session state=TLS13_init_state(&client,hostname);
    TLS_session *session=&state;

#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Hostname= ",hostname,0,NULL);
#endif

    make_client_message(&GET,hostname);

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

    TLS13_connect(session,&GET);  // FULL handshake and connection to server
    TLS13_recv(session,&RESP);    // Server response + ticket
#if VERBOSITY >= IO_APPLICATION
    logger((char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
#endif
    TLS13_clean(session);   // but leave ticket intact
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

    TLS13_connect(session,&GET);  // Resumption handshake and connection to server
    TLS13_recv(session,&RESP);    // Server response + ticket
#if VERBOSITY >= IO_APPLICATION
    logger((char *)"Receiving application data (truncated HTML) = ",NULL,0,&RESP);
#endif

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
