cmake_minimum_required(VERSION 3.7)

# CMake instructions to build tiitls library

# Set the project name
project(tiitls1.3)

if (${SAL} MATCHES MIRACL)
	configure_file(./sal/tls_sal_m.xpp ./src/tls_sal.cpp COPYONLY)
endif ()
if (${SAL} MATCHES MIRACL_TIILIB)
	configure_file(./sal/tls_sal_mt.xpp ./src/tls_sal.cpp COPYONLY)
endif ()
if (${SAL} MATCHES MIRACL_SODIUM)
	configure_file(./sal/tls_sal_ms.xpp ./src/tls_sal.cpp COPYONLY)
endif ()

set(SRC
       ./src/tls_cert_chain.cpp
       ./src/tls_client_recv.cpp
       ./src/tls_client_send.cpp
       ./src/tls_keys_calc.cpp
       ./src/tls_sockets.cpp
       ./src/tls_octads.cpp
       ./src/tls_logger.cpp
       ./src/tls_protocol.cpp
       ./src/tls_cacerts.cpp
       ./src/tls_tickets.cpp
       ./src/tls_x509.cpp
       ./src/tls_sal.cpp
        )

# Add a library
add_library(tiitls STATIC ${SRC})

target_include_directories(tiitls PUBLIC include)

if (${SAL} MATCHES MIRACL)
	target_include_directories(tiitls PUBLIC sal/miracl)
endif ()

if (${SAL} MATCHES MIRACL_SODIUM)
	target_include_directories(tiitls PUBLIC sal/miracl)
endif ()

if (${SAL} MATCHES MIRACL_TIILIB)
	target_include_directories(tiitls PUBLIC sal/miracl)
	target_include_directories(tiitls PUBLIC sal/tii-cryptolib/src)
endif ()


# CMake instructions to build client app

add_executable( client app/client.cpp ) 

target_link_libraries(client tiitls )

if (${SAL} MATCHES MIRACL)
	target_link_libraries(client ${PROJECT_SOURCE_DIR}/sal/miracl/core.a)
endif ()

if (${SAL} MATCHES MIRACL_SODIUM)
	target_link_libraries(client ${PROJECT_SOURCE_DIR}/sal/miracl/core.a -lsodium)
endif ()

if (${SAL} MATCHES MIRACL_TIILIB)
	target_link_libraries(client ${PROJECT_SOURCE_DIR}/sal/tii-cryptolib/cmake-build/src/libtiicrypto-v2.4.0.a)
	target_link_libraries(client ${PROJECT_SOURCE_DIR}/sal/miracl/core.a)
endif ()
