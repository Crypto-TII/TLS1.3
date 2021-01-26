
// Set up and read/write sockets


#include "tls_sockets.h"

int setserversock(int port)
{
    int server_fd, new_socket; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 

    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
        return -1;  // socket failed
       
    // Forcefully attaching socket to the port 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
        return -2; // setsockopt failed
 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( port ); 
       
    // Forcefully attaching socket to the port 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
        return -3;  // bind failed

    if (listen(server_fd, 3) < 0) 
        return -4; // listen failed

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
        return -5; // accept failed

    return new_socket;
}

int setclientsock(int port,char *ip)
{
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        return -1; 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(port); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)  
        return -2; 
    
    struct timeval timeout;
    timeout.tv_sec  = 5;  // after 5 seconds read() will timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
        return -3; 
    
    return sock;
}

// Send Octet
void sendOctet(int sock,octet *B)
{
    send(sock,B->val,B->len,0);
}

// Send Octet length
void sendLen(int sock,int len)
{
    char buff[2];
    octet B={0, sizeof(buff), buff};
    B.len=2;
    B.val[0]=len&0xff;
    B.val[1]=len/256;
    sendOctet(sock,&B);
}

int getBytes(int sock,char *b,int expected)
{
    int more,i=0,len=expected;
    while(len>0)
    {
        more=read(sock,&b[i],len);
        if (more<0) return -1;
        i+=more;
        len-=more;
    }
    return 0;
}

// Get 16-bit Integer from stream
int getInt16(int sock)
{
    char b[2];
    getBytes(sock,b,2);
    return 256*(int)(unsigned char)b[0]+(int)(unsigned char)b[1];
}

// Get 24-bit Integer from stream
int getInt24(int sock)
{
    char b[3];
    getBytes(sock,b,3);
    return 65536*(int)(unsigned char)b[0]+256*(int)(unsigned char)b[1]+(int)(unsigned char)b[2];
}


// Get byte from stream
int getByte(int sock)
{
    char b[1];
    getBytes(sock,b,1);
    return (int)(unsigned char)b[0];
}

// Get expected number of bytes into an octet
int getOctet(int sock,octet *B,int expected)
{
    B->len=expected;
    return getBytes(sock,B->val,expected);
}

int getIPaddress(char *ip,char *hostname)
{
	hostent * record = gethostbyname(hostname);
	if(record == NULL) return 0;
	in_addr * address = (in_addr * )record->h_addr;
	strcpy(ip,inet_ntoa(* address));
    return 1;
}
