/**
 * @file tls_wifi.h
 * @author Mike Scott
 * @brief define Socket structure depending on processor context
 *
 */
// Set up WiFi environment for Arduino boards

#ifndef TLS_WIFI_H
#define TLS_WIFI_H

#include "tls1_3.h"

#ifdef TLS_ARDUINO

#ifdef FISHINO_PIRANHA
// Fishino Piranha board
#define PARTICULAR_BOARD
#include <Fishino.h>
#include <SPI.h>
typedef FishinoClient Socket;
#define WiFi Fishino
#define FISHINO

#endif

#ifdef ESP32
// ESP32 board
#define PARTICULAR_BOARD
#include <WiFi.h>
typedef WiFiClient Socket; 

#endif

#ifndef PARTICULAR_BOARD
// any other board
#include <WiFiNINA.h>
typedef WiFiClient Socket;

#endif
#endif

#endif
