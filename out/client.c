#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

#define CERTSERVER "./certs/CS.pem"
#define KEYSERVER "./certs/CS.key.pem"
#define SM2_SERVER_ENC_CERT "./certs/CE.pem"
#define SM2_SERVER_ENC_KEY  "./certs/CE.key.pem"

#define CHK_ERR(err, s) if((err) == -1) { perror(s); return -1; }else printf("%s  success!\n",s);
#define CHK_RV(rv, s) if((rv) != 1) { printf("%s error\n", s); return -1; }else printf("%s  success!\n",s);
#define CHK_NULL(x, s) if((x) == NULL) { printf("%s error\n", s); return -1; }else printf("%s  success!\n",s);
#define CHK_SSL(err, s) if((err) == -1) { ERR_print_errors_fp(stderr); return -1;}else printf("%s success!\n",s);

//#define SERVER_IP "172.16.21.82"
#define SERVER_IP "127.0.0.1"

//#define SERVER_PORT 64438
#define SERVER_PORT 4438

int main( int argc, char* argv[] )
{
int port;

char *ip;
  int ret;
int rv = 0;
//初始化
SSL_CTX* ctx;
SSL_METHOD *meth;
OpenSSL_add_ssl_algorithms();
SSL_load_error_strings();
//meth = (SSL_METHOD *)TLS_client_method();
meth = (SSL_METHOD *)GMTLS_client_method();
ctx = SSL_CTX_new (meth);

rv = SSL_CTX_use_certificate_file(ctx, CERTSERVER, SSL_FILETYPE_PEM);
CHK_RV(rv, "SSL_CTX_use_certicificate_file");
rv = SSL_CTX_use_PrivateKey_file(ctx, KEYSERVER, SSL_FILETYPE_PEM);
CHK_RV(rv, "SSL_CTX_use_PrivateKey_file");
rv = SSL_CTX_check_private_key(ctx);
CHK_RV(rv, "SSL_CTX_check_private_key");
rv=SSL_CTX_use_certificate_file(ctx,SM2_SERVER_ENC_CERT,SSL_FILETYPE_PEM);
CHK_RV(rv, "SSL_CTX_use_certicificate_file2");
rv=SSL_CTX_use_PrivateKey_file(ctx,SM2_SERVER_ENC_KEY,SSL_FILETYPE_PEM);

CHK_RV(rv, "SSL_CTX_use_PrivateKey_file2");	
rv = SSL_CTX_check_private_key(ctx);	

ip=SERVER_IP;
port=SERVER_PORT;
if(argc>=3)
{
ip = argv[1];
port=atoi(argv[2]);
}

if (!ctx) {

    ERR_print_errors_fp(stderr);
std::cout<<"SSL_CTX_new error."<<std::endl;

    return -1;

  }
//SSL_CTX_set_cipher_list(ctx, "ECDHE-SM2-WITH-SMS4-SM3");
//SSL_CTX_set_cipher_list(ctx, "SM2-WITH-SMS4-SM3");
//SSL_CTX_set_cipher_list(ctx, "ECDHE-SM2-WITH-SMS4-SM3");
//SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384");
//  SSL_CTX_set_max_proto_version(ctx,TLS1_2_VERSION);
//  SSL_CTX_set_min_proto_version(ctx,TLS1_2_VERSION);

//建立原始的TCP连接
int client_socket;
struct sockaddr_in addr_server;
client_socket = socket (AF_INET, SOCK_STREAM, 0);
if(client_socket==-1)
{
std::cout<<"socket error."<<std::endl;
return -1;
}

memset (&addr_server, 0, sizeof(addr_server));
addr_server.sin_family=AF_INET;
addr_server.sin_addr.s_addr = inet_addr(ip);
//addr_server.sin_addr.s_addr = inet_addr(SERVER_IP);
addr_server.sin_port = htons (port);
//addr_server.sin_port = htons (SERVER_PORT);
ret = connect(client_socket, (struct sockaddr*) &addr_server, sizeof(addr_server));

 if( ret == -1  ) {

    std::cout<<"connect error."<<std::endl;

    return -1;

  }
//TCP连接已经建立，执行Client SSL
SSL* ssl;
X509* server_certificate;
char* str;
ssl=SSL_new (ctx);
if( ssl == NULL )
{
std::cout<<"SSL_new error."<<std::endl;
return -1;
}
SSL_set_fd(ssl,client_socket);
ret=SSL_connect(ssl);
if( ret == -1 )
{
std::cout<<"SSL_connect error."<<std::endl;
ERR_print_errors_fp(stderr); return -1;
}
ERR_print_errors_fp(stderr);

//接下来的获取密码和获取服务器端证书的两部是可选的，不会影响数据交换
// 获取cipher
 std::cout<<"SSL connection using: "<<SSL_get_cipher(ssl)<<std::endl;

//获取服务器端的证书
server_certificate = SSL_get_peer_certificate (ssl); 
if( server_certificate != NULL )
{
std::cout<<"Server certificate:"<<std::endl;
str = X509_NAME_oneline (X509_get_subject_name (server_certificate),0,0);
if( str == NULL )
{
std::cout<<"X509_NAME_oneline error."<<std::endl;
}
else
{
std::cout<<"subject: "<<str<<std::endl;
OPENSSL_free (str);
}
str = X509_NAME_oneline(X509_get_issuer_name(server_certificate),0,0);
if( str == NULL )
{
std::cout<<"X509_NAME_oneline error."<<std::endl;
}
else
{
std::cout<<"issuer: "<<str<<std::endl;
OPENSSL_free (str);
}
X509_free (server_certificate);
} 
else
{
std::cout<<"Server does not have certificate. we sould Esc!"<<std::endl;
return -1;
}

// 数据交换
char buf [4096];
ret = SSL_write (ssl, "Hello World!", strlen("Hello World!"));
if( ret == -1 )
{
std::cout<<"SSL_write error."<<std::endl;
return -1;
}

ret = SSL_read (ssl, buf, sizeof(buf) - 1);
if( ret == -1 )
{
std::cout<<"SSL_read error."<<std::endl;
return -1;
}
buf[ret] = '\0';
std::cout<<buf<<std::endl;
SSL_shutdown(ssl);

close(client_socket);
SSL_free (ssl);
SSL_CTX_free (ctx);
return 0;

}
