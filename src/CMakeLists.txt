cmake_minimum_required(VERSION 3.7)

# Set the project name
project(tiitls1.3)

set(HDR
        tls1_3.h
        tls_sockets.h
        tls1_3.h
        tls_cert_chain.h
        tls_client_recv.h
        tls_client_send.h
        tls_hash.h
        tls_keys_calc.h
        tls_parse_octet.h
        tls_sockets.h
        tls_tickets.h
        )
set(SRC
       tls_cert_chain.cpp
       tls_client_recv.cpp
       tls_client_send.cpp
       tls_hash.cpp
       tls_keys_calc.cpp
       tls_parse_octet.cpp
       tls_sockets.cpp
       tls_tickets.cpp
        )

# Add a library
add_library(prod_lib OBJECT ${SRC})

include_directories(${CMAKE_SOURCE_DIR}/vendor/miracl/includes)
target_link_libraries(prod_lib
        ${CMAKE_SOURCE_DIR}/vendor/miracl/core.a
        )

install(FILES ${HDR} DESTINATION includes)


add_executable(client
        client.cpp
        )
target_link_libraries(client
        prod_lib
        )

add_executable(server
        server.cpp
        )
target_link_libraries(server
        prod_lib
        )


