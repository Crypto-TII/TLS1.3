# Install script for directory: /Users/alvaro/Documents/project/tii/tls13/TLS1.3/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/includes" TYPE FILE FILES
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls1_3.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_sockets.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/vendor/miracl/includes/arch.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls1_3.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_cert_chain.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_client_recv.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_client_send.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_hash.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_keys_calc.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_parse_octet.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_sockets.h"
    "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/tls_tickets.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/alvaro/Documents/project/tii/tls13/TLS1.3/src/cmake-build-debug/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
