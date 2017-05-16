// Copyright (c) Athena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "cbasetypes.h"
#include "mmo.h"
#include "timer.h"
#include "malloc.h"
#include "showmsg.h"
#include "strlib.h"
#include "socket.h"
#include "core.h"

#include <stdlib.h>

#ifdef WIN32
	#include "winapi.h"
#else
	#include <errno.h>
#include <netinet/tcp.h>
	#include <net/if.h>
	#include <unistd.h>
#include <sys/ioctl.h>
	#include <netdb.h>
	#include <arpa/inet.h>

	#ifndef SIOCGIFCONF
	#include <sys/sockio.h> // SIOCGIFCONF on Solaris, maybe others? [Shinomori]
	#endif
	#ifndef FIONBIO
	#include <sys/filio.h> // FIONBIO on Solaris [FlavioJS]
	#endif

	#ifdef HAVE_SETRLIMIT
	#include <sys/resource.h>
	#endif
#endif

/////////////////////////////////////////////////////////////////////
#if defined(WIN32)
/////////////////////////////////////////////////////////////////////
// windows portability layer

typedef int socklen_t;

#define sErrno WSAGetLastError()
#define S_ENOTSOCK WSAENOTSOCK
#define S_EWOULDBLOCK WSAEWOULDBLOCK
#define S_EINTR WSAEINTR
#define S_ECONNABORTED WSAECONNABORTED

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

// global array of sockets (emulating linux)
// fd is the position in the array
static SOCKET sock_arr[FD_SETSIZE];
static int sock_arr_len = 0;

/// Returns the socket associated with the target fd.
///
/// @param fd Target fd.
/// @return Socket
#define fd2sock(fd) sock_arr[fd]

/// Returns the first fd associated with the socket.
/// Returns -1 if the socket is not found.
///
/// @param s Socket
/// @return Fd or -1
int sock2fd(SOCKET s)
{
	int fd;

	// search for the socket
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == s )
			break;// found the socket
	if( fd == sock_arr_len )
		return -1;// not found
	return fd;
}


/// Inserts the socket into the global array of sockets.
/// Returns a new fd associated with the socket.
/// If there are too many sockets it closes the socket, sets an error and
//  returns -1 instead.
/// Since fd 0 is reserved, it returns values in the range [1,FD_SETSIZE[.
///
/// @param s Socket
/// @return New fd or -1
int sock2newfd(SOCKET s)
{
	int fd;

	// find an empty position
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == INVALID_SOCKET )
			break;// empty position
	if( fd == ARRAYLENGTH(sock_arr) )
	{// too many sockets
		closesocket(s);
		WSASetLastError(WSAEMFILE);
		return -1;
	}
	sock_arr[fd] = s;
	if( sock_arr_len <= fd )
		sock_arr_len = fd+1;
	return fd;
}

int sAccept(int fd, struct sockaddr* addr, int* addrlen)
{
	SOCKET s;

	// accept connection
	s = accept(fd2sock(fd), addr, addrlen);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

int sClose(int fd)
{
	int ret = closesocket(fd2sock(fd));
	fd2sock(fd) = INVALID_SOCKET;
	return ret;
}

int sSocket(int af, int type, int protocol)
{
	SOCKET s;

	// create socket
	s = socket(af,type,protocol);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

char* sErr(int code)
{
	static char sbuf[512];
	// strerror does not handle socket codes
	if( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
			code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&sbuf, sizeof(sbuf), NULL) == 0 )
		snprintf(sbuf, sizeof(sbuf), "unknown error");
	return sbuf;
}

#define sBind(fd,name,namelen) bind(fd2sock(fd),name,namelen)
#define sConnect(fd,name,namelen) connect(fd2sock(fd),name,namelen)
#define sIoctl(fd,cmd,argp) ioctlsocket(fd2sock(fd),cmd,argp)
#define sListen(fd,backlog) listen(fd2sock(fd),backlog)
#define sRecv(fd,buf,len,flags) recv(fd2sock(fd),buf,len,flags)
#define sSelect select
#define sSend(fd,buf,len,flags) send(fd2sock(fd),buf,len,flags)
#define sSetsockopt(fd,level,optname,optval,optlen) setsockopt(fd2sock(fd),level,optname,optval,optlen)
#define sShutdown(fd,how) shutdown(fd2sock(fd),how)
#define sFD_SET(fd,set) FD_SET(fd2sock(fd),set)
#define sFD_CLR(fd,set) FD_CLR(fd2sock(fd),set)
#define sFD_ISSET(fd,set) FD_ISSET(fd2sock(fd),set)
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#else
/////////////////////////////////////////////////////////////////////
// nix portability layer

#define SOCKET_ERROR (-1)

#define sErrno errno
#define S_ENOTSOCK EBADF
#define S_EWOULDBLOCK EAGAIN
#define S_EINTR EINTR
#define S_ECONNABORTED ECONNABORTED

#define sAccept accept
#define sClose close
#define sSocket socket
#define sErr strerror

#define sBind bind
#define sConnect connect
#define sIoctl ioctl
#define sListen listen
#define sRecv recv
#define sSelect select
#define sSend send
#define sSetsockopt setsockopt
#define sShutdown shutdown
#define sFD_SET FD_SET
#define sFD_CLR FD_CLR
#define sFD_ISSET FD_ISSET
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#endif
/////////////////////////////////////////////////////////////////////

#ifndef MSG_NOSIGNAL
	#define MSG_NOSIGNAL 0
#endif

fd_set readfds;
int fd_max;
time_t last_tick;
time_t stall_time = 60;

uint32 addr_[16];   // ip addresses of local host (host byte order)
int naddr_ = 0;   // # of ip addresses

// Maximum packet size in bytes, which the client is able to handle.
// Larger packets cause a buffer overflow and stack corruption.
#if PACKETVER < 20131223
static size_t socket_max_client_packet = 0x6000;
#else
static size_t socket_max_client_packet = USHRT_MAX;
#endif

#ifdef SHOW_SERVER_STATS
// Data I/O statistics
static size_t socket_data_i = 0, socket_data_ci = 0, socket_data_qi = 0;
static size_t socket_data_o = 0, socket_data_co = 0, socket_data_qo = 0;
static time_t socket_data_last_tick = 0;
#endif

// initial recv buffer size (this will also be the max. size)
// biggest known packet: S 0153 <len>.w <emblem data>.?B -> 24x24 256 color .bmp (0153 + len.w + 1618/1654/1756 bytes)
#define RFIFO_SIZE (2*1024)
// initial send buffer size (will be resized as needed)
#define WFIFO_SIZE (16*1024)

// Maximum size of pending data in the write fifo. (for non-server connections)
// The connection is closed if it goes over the limit.
#define WFIFO_MAX (1*1024*1024)

struct socket_data* session[FD_SETSIZE];

#ifdef SEND_SHORTLIST
int send_shortlist_array[FD_SETSIZE];// we only support FD_SETSIZE sockets, limit the array to that
int send_shortlist_count = 0;// how many fd's are in the shortlist
uint32 send_shortlist_set[(FD_SETSIZE+31)/32];// to know if specific fd's are already in the shortlist
#endif

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse);

#ifndef MINICORE
	int ip_rules = 1;
	static int connect_check(uint32 ip);
#endif

const char* error_msg(void)
{
	static char buf[512];
	int code = sErrno;
	snprintf(buf, sizeof(buf), "error %d: %s", code, sErr(code));
	return buf;
}

/*======================================
 *	CORE : Default processing functions
 *--------------------------------------*/
int null_recv(int fd) { return 0; }
int null_send(int fd) { return 0; }
int null_parse(int fd) { return 0; }

ParseFunc default_func_parse = null_parse;

void set_defaultparse(ParseFunc defaultparse)
{
	default_func_parse = defaultparse;
}


/*======================================
 *	CORE : Socket options
 *--------------------------------------*/
void set_nonblocking(int fd, unsigned long yes)
{
	// FIONBIO Use with a nonzero argp parameter to enable the nonblocking mode of socket s.
	// The argp parameter is zero if nonblocking is to be disabled.
	if( sIoctl(fd, FIONBIO, &yes) != 0 )
		ShowError("set_nonblocking: Failed to set socket #%d to non-blocking mode (%s) - Please report this!!!\n", fd, error_msg());
}

void setsocketopts(int fd,int delay_timeout){
	int yes = 1; // reuse fix

#if !defined(WIN32)
	// set SO_REAUSEADDR to true, unix only. on windows this option causes
	// the previous owner of the socket to give up, which is not desirable
	// in most cases, neither compatible with unix.
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&yes,sizeof(yes));
#ifdef SO_REUSEPORT
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEPORT,(char *)&yes,sizeof(yes));
#endif
#endif

	// Set the socket into no-delay mode; otherwise packets get delayed for up to 200ms, likely creating server-side lag.
	// The RO protocol is mainly single-packet request/response, plus the FIFO model already does packet grouping anyway.
	sSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

	// force the socket into no-wait, graceful-close mode (should be the default, but better make sure)
	//(https://msdn.microsoft.com/en-us/library/windows/desktop/ms737582%28v=vs.85%29.aspx)
	{
		struct linger opt;
		opt.l_onoff = 0; // SO_DONTLINGER
		opt.l_linger = 0; // Do not care
		if( sSetsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&opt, sizeof(opt)) )
			ShowWarning("setsocketopts: Unable to set SO_LINGER mode for connection #%d!\n", fd);
	}
	if(delay_timeout){
#if defined(WIN32)
		int timeout = delay_timeout * 1000;
#else
		struct timeval timeout;
		timeout.tv_sec = delay_timeout;
		timeout.tv_usec = 0;
#endif

		if (sSetsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_RCVTIMEO timeout for connection #%d!\n");
		if (sSetsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_SNDTIMEO timeout for connection #%d!\n");
	}
}

/*======================================
 *	CORE : Socket Sub Function
 *--------------------------------------*/
void set_eof(int fd)
{
	if( session_isActive(fd) )
	{
#ifdef SEND_SHORTLIST
		// Add this socket to the shortlist for eof handling.
		send_shortlist_add_fd(fd);
#endif
		session[fd]->flag.eof = 1;
	}
}

int recv_to_fifo(int fd)
{
	int len;

	if( !session_isActive(fd) )
		return -1;

	len = sRecv(fd, (char *) session[fd]->rdata + session[fd]->rdata_size, (int)RFIFOSPACE(fd), 0);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("recv_to_fifo: %s, closing connection #%d\n", error_msg(), fd);
			set_eof(fd);
		}
		return 0;
	}

	if( len == 0 )
	{//Normal connection end.
		set_eof(fd);
		return 0;
	}

	session[fd]->rdata_size += len;
	session[fd]->rdata_tick = last_tick;
#ifdef SHOW_SERVER_STATS
	socket_data_i += len;
	socket_data_qi += len;
	if (!session[fd]->flag.server)
	{
		socket_data_ci += len;
	}
#endif
	return 0;
}

int send_from_fifo(int fd)
{
	int len;

	if( !session_isValid(fd) )
		return -1;

	if( session[fd]->wdata_size == 0 )
		return 0; // nothing to send

	len = sSend(fd, (const char *) session[fd]->wdata, (int)session[fd]->wdata_size, MSG_NOSIGNAL);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("send_from_fifo: %s, ending connection #%d\n", error_msg(), fd);
#ifdef SHOW_SERVER_STATS
			socket_data_qo -= session[fd]->wdata_size;
#endif
			session[fd]->wdata_size = 0; //Clear the send queue as we can't send anymore. [Skotlex]
			set_eof(fd);
		}
		return 0;
	}

	if( len > 0 )
	{
		// some data could not be transferred?
		// shift unsent data to the beginning of the queue
		if( (size_t)len < session[fd]->wdata_size )
			memmove(session[fd]->wdata, session[fd]->wdata + len, session[fd]->wdata_size - len);

		session[fd]->wdata_size -= len;
#ifdef SHOW_SERVER_STATS
		socket_data_o += len;
		socket_data_qo -= len;
		if (!session[fd]->flag.server)
		{
			socket_data_co += len;
		}
#endif
	}

	return 0;
}

/// Best effort - there's no warranty that the data will be sent.
void flush_fifo(int fd)
{
	if(session[fd] != NULL)
		session[fd]->func_send(fd);
}

void flush_fifos(void)
{
	int i;
	for(i = 1; i < fd_max; i++)
		flush_fifo(i);
}

/*======================================
 *	CORE : Connection functions
 *--------------------------------------*/
int connect_client(int listen_fd)
{
	int fd;
	struct sockaddr_in client_address;
	socklen_t len;

	len = sizeof(client_address);

	fd = sAccept(listen_fd, (struct sockaddr*)&client_address, &len);
	if ( fd == -1 ) {
		ShowError("connect_client: accept failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("connect_client: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("connect_client: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

#ifndef MINICORE
	if( ip_rules && !connect_check(ntohl(client_address.sin_addr.s_addr)) ) {
		do_close(fd);
		return -1;
	}
#endif

	if( fd_max <= fd ) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(client_address.sin_addr.s_addr);

	return fd;
}

int make_listen_bind(uint32 ip, uint16 port)
{
	struct sockaddr_in server_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if( fd == -1 )
	{
		ShowError("make_listen_bind: socket creation failed (%s)!\n", error_msg());
		exit(EXIT_FAILURE);
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_listen_bind: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_listen_bind: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

	server_address.sin_family      = AF_INET;
	server_address.sin_addr.s_addr = htonl(ip);
	server_address.sin_port        = htons(port);

	result = sBind(fd, (struct sockaddr*)&server_address, sizeof(server_address));
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: bind failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}
	result = sListen(fd,5);
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: listen failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}

	if(fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd, &readfds);

	create_session(fd, connect_client, null_send, null_parse);
	session[fd]->client_addr = 0; // just listens
	session[fd]->rdata_tick = 0; // disable timeouts on this socket

	return fd;
}

int make_connection(uint32 ip, uint16 port, bool silent,int timeout) {
	struct sockaddr_in remote_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if (fd == -1) {
		ShowError("make_connection: socket creation failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_connection: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_connection: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,timeout);

	remote_address.sin_family      = AF_INET;
	remote_address.sin_addr.s_addr = htonl(ip);
	remote_address.sin_port        = htons(port);

	if( !silent )
		ShowStatus("Connecting to %d.%d.%d.%d:%i\n", CONVIP(ip), port);
#ifdef WIN32
	// On Windows we have to set the socket non-blocking before the connection to make timeout work. [Lemongrass]
	set_nonblocking(fd, 1);

	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));

	// Only enter if a socket error occurred
	// Create a pseudo scope to be able to break out in case of successful connection
	while( result == SOCKET_ERROR ) {
		// Specially handle the error number for connection attempts that would block, because we want to use a timeout
		if( sErrno == S_EWOULDBLOCK ){
			fd_set writeSet;
			struct timeval tv;

			sFD_ZERO(&writeSet);
			sFD_SET(fd,&writeSet);

			tv.tv_sec = timeout;
			tv.tv_usec = 0;

			result = sSelect(0, NULL, &writeSet, NULL, &tv);

			// Connection attempt timed out
			if( result == 0 ){
				if( !silent ){
					// Needs special handling, because it does not set an error code and therefore does not provide an error message from the API
					ShowError("make_connection: connection failed (socket #%d, timeout after %ds)!\n", fd, timeout);
				}

				do_close(fd);
				return -1;
			// If the select operation did not return an error
			}else if( result != SOCKET_ERROR ){
				// Check if it is really writeable
				if( sFD_ISSET(fd, &writeSet) != 0 ){
					// Our socket is writeable now => we have connected successfully
					break; // leave the pseudo scope
				}

				if( !silent ){
					// Needs special handling, because it does not set an error code and therefore does not provide an error message from the API
					ShowError("make_connection: connection failed (socket #%d, not writeable)!\n", fd);
				}

				do_close(fd);
				return -1;
			}
			// The select operation failed
		}

		if( !silent )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());

		do_close(fd);
		return -1;
	}
	// Keep the socket in non-blocking mode, since we would set it to non-blocking here on unix. [Lemongrass]
#else
	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));
	if( result == SOCKET_ERROR ) {
		if( !silent )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());
		do_close(fd);
		return -1;
	}

	//Now the socket can be made non-blocking. [Skotlex]
	set_nonblocking(fd, 1);
#endif

	if (fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(remote_address.sin_addr.s_addr);

	return fd;
}

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse)
{
	CREATE(session[fd], struct socket_data, 1);
	CREATE(session[fd]->rdata, unsigned char, RFIFO_SIZE);
	CREATE(session[fd]->wdata, unsigned char, WFIFO_SIZE);
	session[fd]->max_rdata  = RFIFO_SIZE;
	session[fd]->max_wdata  = WFIFO_SIZE;
	session[fd]->func_recv  = func_recv;
	session[fd]->func_send  = func_send;
	session[fd]->func_parse = func_parse;
	session[fd]->rdata_tick = last_tick;
	return 0;
}

static void delete_session(int fd)
{
	if( session_isValid(fd) )
	{
#ifdef SHOW_SERVER_STATS
		socket_data_qi -= session[fd]->rdata_size - session[fd]->rdata_pos;
		socket_data_qo -= session[fd]->wdata_size;
#endif
		aFree(session[fd]->rdata);
		aFree(session[fd]->wdata);
		aFree(session[fd]->session_data);
		aFree(session[fd]);
		session[fd] = NULL;
	}
}

int realloc_fifo(int fd, unsigned int rfifo_size, unsigned int wfifo_size)
{
	if( !session_isValid(fd) )
		return 0;

	if( session[fd]->max_rdata != rfifo_size && session[fd]->rdata_size < rfifo_size) {
		RECREATE(session[fd]->rdata, unsigned char, rfifo_size);
		session[fd]->max_rdata  = rfifo_size;
	}

	if( session[fd]->max_wdata != wfifo_size && session[fd]->wdata_size < wfifo_size) {
		RECREATE(session[fd]->wdata, unsigned char, wfifo_size);
		session[fd]->max_wdata  = wfifo_size;
	}
	return 0;
}

int realloc_writefifo(int fd, size_t addition)
{
	size_t newsize;

	if( !session_isValid(fd) ) // might not happen
		return 0;

	if( session[fd]->wdata_size + addition  > session[fd]->max_wdata )
	{	// grow rule; grow in multiples of WFIFO_SIZE
		newsize = WFIFO_SIZE;
		while( session[fd]->wdata_size + addition > newsize ) newsize += WFIFO_SIZE;
	}
	else
	if( session[fd]->max_wdata >= (size_t)2*(session[fd]->flag.server?FIFOSIZE_SERVERLINK:WFIFO_SIZE)
		&& (session[fd]->wdata_size+addition)*4 < session[fd]->max_wdata )
	{	// shrink rule, shrink by 2 when only a quarter of the fifo is used, don't shrink below nominal size.
		newsize = session[fd]->max_wdata / 2;
	}
	else // no change
		return 0;

	RECREATE(session[fd]->wdata, unsigned char, newsize);
	session[fd]->max_wdata  = newsize;

	return 0;
}

/// advance the RFIFO cursor (marking 'len' bytes as processed)
int RFIFOSKIP(int fd, size_t len)
{
    struct socket_data *s;

	if ( !session_isActive(fd) )
		return 0;

	s = session[fd];

	if ( s->rdata_size < s->rdata_pos + len ) {
		ShowError("RFIFOSKIP: skipped past end of read buffer! Adjusting from %d to %d (session #%d)\n", len, RFIFOREST(fd), fd);
		len = RFIFOREST(fd);
	}

	s->rdata_pos = s->rdata_pos + len;
#ifdef SHOW_SERVER_STATS
	socket_data_qi -= len;
#endif
	return 0;
}

/// advance the WFIFO cursor (marking 'len' bytes for sending)
int WFIFOSET(int fd, size_t len)
{
	size_t newreserve;
	struct socket_data* s = session[fd];

	if( !session_isValid(fd) || s->wdata == NULL )
		return 0;

	// we have written len bytes to the buffer already before calling WFIFOSET
	if(s->wdata_size+len > s->max_wdata)
	{	// actually there was a buffer overflow already
		uint32 ip = s->client_addr;
		ShowFatalError("WFIFOSET: Write Buffer Overflow. Connection %d (%d.%d.%d.%d) has written %u bytes on a %u/%u bytes buffer.\n", fd, CONVIP(ip), (unsigned int)len, (unsigned int)s->wdata_size, (unsigned int)s->max_wdata);
		ShowDebug("Likely command that caused it: 0x%x\n", (*(uint16*)(s->wdata + s->wdata_size)));
		// no other chance, make a better fifo model
		exit(EXIT_FAILURE);
	}

	if( len > 0xFFFF )
	{
		// dynamic packets allow up to UINT16_MAX bytes (<packet_id>.W <packet_len>.W ...)
		// all known fixed-size packets are within this limit, so use the same limit
		ShowFatalError("WFIFOSET: Packet 0x%x is too big. (len=%u, max=%u)\n", (*(uint16*)(s->wdata + s->wdata_size)), (unsigned int)len, 0xFFFF);
		exit(EXIT_FAILURE);
	}
	else if( len == 0 )
	{
		// abuses the fact, that the code that did WFIFOHEAD(fd,0), already wrote
		// the packet type into memory, even if it could have overwritten vital data
		// this can happen when a new packet was added on map-server, but packet len table was not updated
		ShowWarning("WFIFOSET: Attempted to send zero-length packet, most likely 0x%04x (please report this).\n", WFIFOW(fd,0));
		return 0;
	}

	if( !s->flag.server ) {

		if( len > socket_max_client_packet ) {// see declaration of socket_max_client_packet for details
			ShowError("WFIFOSET: Dropped too large client packet 0x%04x (length=%u, max=%u).\n", WFIFOW(fd,0), len, socket_max_client_packet);
			return 0;
		}

		if( s->wdata_size+len > WFIFO_MAX ) {// reached maximum write fifo size
			ShowError("WFIFOSET: Maximum write buffer size for client connection %d exceeded, most likely caused by packet 0x%04x (len=%u, ip=%lu.%lu.%lu.%lu).\n", fd, WFIFOW(fd,0), len, CONVIP(s->client_addr));
			set_eof(fd);
			return 0;
		}

	}

        // Gepard Shield
        if (is_gepard_active == true && SERVER_TYPE != ATHENA_SERVER_CHAR)
        {
                gepard_process_packet(fd, s->wdata + s->wdata_size, len, &s->send_crypt);
        }
        // Gepard Shield

	s->wdata_size += len;
#ifdef SHOW_SERVER_STATS
	socket_data_qo += len;
#endif
	//If the interserver has 200% of its normal size full, flush the data.
	if( s->flag.server && s->wdata_size >= 2*FIFOSIZE_SERVERLINK )
		flush_fifo(fd);

	// always keep a WFIFO_SIZE reserve in the buffer
	// For inter-server connections, let the reserve be 1/4th of the link size.
	newreserve = s->flag.server ? FIFOSIZE_SERVERLINK / 4 : WFIFO_SIZE;

	// readjust the buffer to include the chosen reserve
	realloc_writefifo(fd, newreserve);

#ifdef SEND_SHORTLIST
	send_shortlist_add_fd(fd);
#endif

	return 0;
}

int do_sockets(int next)
{
	fd_set rfd;
	struct timeval timeout;
	int ret,i;

	// PRESEND Timers are executed before do_sendrecv and can send packets and/or set sessions to eof.
	// Send remaining data and process client-side disconnects here.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);
	}
#endif

	// can timeout until the next tick
	timeout.tv_sec  = next/1000;
	timeout.tv_usec = next%1000*1000;

	memcpy(&rfd, &readfds, sizeof(rfd));
	ret = sSelect(fd_max, &rfd, NULL, NULL, &timeout);

	if( ret == SOCKET_ERROR )
	{
		if( sErrno != S_EINTR )
		{
			ShowFatalError("do_sockets: select() failed, %s!\n", error_msg());
			exit(EXIT_FAILURE);
		}
		return 0; // interrupted by a signal, just loop and try again
	}

	last_tick = time(NULL);

#if defined(WIN32)
	// on windows, enumerating all members of the fd_set is way faster if we access the internals
	for( i = 0; i < (int)rfd.fd_count; ++i )
	{
		int fd = sock2fd(rfd.fd_array[i]);
		if( session[fd] )
			session[fd]->func_recv(fd);
	}
#else
	// otherwise assume that the fd_set is a bit-array and enumerate it in a standard way
	for( i = 1; ret && i < fd_max; ++i )
	{
		if(sFD_ISSET(i,&rfd) && session[i])
		{
			session[i]->func_recv(i);
			--ret;
		}
	}
#endif

	// POSTSEND Send remaining data and handle eof sessions.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);

		if(session[i]->flag.eof) //func_send can't free a session, this is safe.
		{	//Finally, even if there is no data to parse, connections signalled eof should be closed, so we call parse_func [Skotlex]
			session[i]->func_parse(i); //This should close the session immediately.
		}
	}
#endif

	// parse input data on each socket
	for(i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if (session[i]->rdata_tick && DIFF_TICK(last_tick, session[i]->rdata_tick) > stall_time) {
			if( session[i]->flag.server ) {/* server is special */
				if( session[i]->flag.ping != 2 )/* only update if necessary otherwise it'd resend the ping unnecessarily */
					session[i]->flag.ping = 1;
			} else {
				ShowInfo("Session #%d timed out\n", i);
				set_eof(i);
			}
		}

		session[i]->func_parse(i);

		if(!session[i])
			continue;

		// after parse, check client's RFIFO size to know if there is an invalid packet (too big and not parsed)
		if (session[i]->rdata_size == RFIFO_SIZE && session[i]->max_rdata == RFIFO_SIZE) {
			set_eof(i);
			continue;
		}
		RFIFOFLUSH(i);
	}

#ifdef SHOW_SERVER_STATS
	if (last_tick != socket_data_last_tick)
	{
		char buf[1024];
		
		sprintf(buf, "In: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | Out: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | RAM: %.03f MB", socket_data_i/1024., socket_data_ci/1024., socket_data_qi/1024., socket_data_o/1024., socket_data_co/1024., socket_data_qo/1024., malloc_usage()/1024.);
#ifdef _WIN32
		SetConsoleTitle(buf);
#else
		ShowMessage("\033[s\033[1;1H\033[2K%s\033[u", buf);
#endif
		socket_data_last_tick = last_tick;
		socket_data_i = socket_data_ci = 0;
		socket_data_o = socket_data_co = 0;
	}
#endif

	return 0;
}

//////////////////////////////
#ifndef MINICORE
//////////////////////////////
// IP rules and DDoS protection

typedef struct _connect_history {
	struct _connect_history* next;
	uint32 ip;
	uint32 tick;
	int count;
	unsigned ddos : 1;
} ConnectHistory;

typedef struct _access_control {
	uint32 ip;
	uint32 mask;
} AccessControl;

enum _aco {
	ACO_DENY_ALLOW,
	ACO_ALLOW_DENY,
	ACO_MUTUAL_FAILURE
};

static AccessControl* access_allow = NULL;
static AccessControl* access_deny = NULL;
static int access_order    = ACO_DENY_ALLOW;
static int access_allownum = 0;
static int access_denynum  = 0;
static int access_debug    = 0;
static int ddos_count      = 10;
static int ddos_interval   = 3*1000;
static int ddos_autoreset  = 10*60*1000;
/// Connection history, an array of linked lists.
/// The array's index for any ip is ip&0xFFFF
static ConnectHistory* connect_history[0x10000];

static int connect_check_(uint32 ip);

/// Verifies if the IP can connect. (with debug info)
/// @see connect_check_()
static int connect_check(uint32 ip)
{
	int result = connect_check_(ip);
	if( access_debug ) {
		ShowInfo("connect_check: Connection from %d.%d.%d.%d %s\n", CONVIP(ip),result ? "allowed." : "denied!");
	}
	return result;
}

/// Verifies if the IP can connect.
///  0      : Connection Rejected
///  1 or 2 : Connection Accepted
static int connect_check_(uint32 ip)
{
	ConnectHistory* hist = connect_history[ip&0xFFFF];
	int i;
	int is_allowip = 0;
	int is_denyip = 0;
	int connect_ok = 0;

	// Search the allow list
	for( i=0; i < access_allownum; ++i ){
		if( (ip & access_allow[i].mask) == (access_allow[i].ip & access_allow[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from allow list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_allow[i].ip),
					CONVIP(access_allow[i].mask));
			}
			is_allowip = 1;
			break;
		}
	}
	// Search the deny list
	for( i=0; i < access_denynum; ++i ){
		if( (ip & access_deny[i].mask) == (access_deny[i].ip & access_deny[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from deny list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_deny[i].ip),
					CONVIP(access_deny[i].mask));
			}
			is_denyip = 1;
			break;
		}
	}
	// Decide connection status
	//  0 : Reject
	//  1 : Accept
	//  2 : Unconditional Accept (accepts even if flagged as DDoS)
	switch(access_order) {
	case ACO_DENY_ALLOW:
	default:
		if( is_denyip )
			connect_ok = 0; // Reject
		else if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 1; // Accept
		break;
	case ACO_ALLOW_DENY:
		if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else if( is_denyip )
			connect_ok = 0; // Reject
		else
			connect_ok = 1; // Accept
		break;
	case ACO_MUTUAL_FAILURE:
		if( is_allowip && !is_denyip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 0; // Reject
		break;
	}

	// Inspect connection history
	while( hist ) {
		if( ip == hist->ip )
		{// IP found
			if( hist->ddos )
			{// flagged as DDoS
				return (connect_ok == 2 ? 1 : 0);
			} else if( DIFF_TICK(gettick(),hist->tick) < ddos_interval )
			{// connection within ddos_interval
				hist->tick = gettick();
				if( hist->count++ >= ddos_count )
				{// DDoS attack detected
					hist->ddos = 1;
					ShowWarning("connect_check: DDoS Attack detected from %d.%d.%d.%d!\n", CONVIP(ip));
					return (connect_ok == 2 ? 1 : 0);
				}
				return connect_ok;
			} else
			{// not within ddos_interval, clear data
				hist->tick  = gettick();
				hist->count = 0;
				return connect_ok;
			}
		}
		hist = hist->next;
	}
	// IP not found, add to history
	CREATE(hist, ConnectHistory, 1);
	memset(hist, 0, sizeof(ConnectHistory));
	hist->ip   = ip;
	hist->tick = gettick();
	hist->next = connect_history[ip&0xFFFF];
	connect_history[ip&0xFFFF] = hist;
	return connect_ok;
}

/// Timer function.
/// Deletes old connection history records.
static int connect_check_clear(int tid, unsigned int tick, int id, intptr_t data)
{
	int i;
	int clear = 0;
	int list  = 0;
	ConnectHistory root;
	ConnectHistory* prev_hist;
	ConnectHistory* hist;

	for( i=0; i < 0x10000 ; ++i ){
		prev_hist = &root;
		root.next = hist = connect_history[i];
		while( hist ){
			if( (!hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_interval*3) ||
					(hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_autoreset) )
			{// Remove connection history
				prev_hist->next = hist->next;
				aFree(hist);
				hist = prev_hist->next;
				clear++;
			} else {
				prev_hist = hist;
				hist = hist->next;
			}
			list++;
		}
		connect_history[i] = root.next;
	}
	if( access_debug ){
		ShowInfo("connect_check_clear: Cleared %d of %d from IP list.\n", clear, list);
	}
	return list;
}

/// Parses the ip address and mask and puts it into acc.
/// Returns 1 is successful, 0 otherwise.
int access_ipmask(const char* str, AccessControl* acc)
{
	uint32 ip;
	uint32 mask;

	if( strcmp(str,"all") == 0 ) {
		ip   = 0;
		mask = 0;
	} else {
		unsigned int a[4];
		unsigned int m[4];
		int n;
		if( ((n=sscanf(str,"%3u.%3u.%3u.%3u/%3u.%3u.%3u.%3u",a,a+1,a+2,a+3,m,m+1,m+2,m+3)) != 8 && // not an ip + standard mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u/%3u",a,a+1,a+2,a+3,m)) != 5 && // not an ip + bit mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u",a,a+1,a+2,a+3)) != 4 ) || // not an ip
				a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 || // invalid ip
				(n == 8 && (m[0] > 255 || m[1] > 255 || m[2] > 255 || m[3] > 255)) || // invalid standard mask
				(n == 5 && m[0] > 32) ){ // invalid bit mask
			return 0;
		}
		ip = MAKEIP(a[0],a[1],a[2],a[3]);
		if( n == 8 )
		{// standard mask
			mask = MAKEIP(m[0],m[1],m[2],m[3]);
		} else if( n == 5 )
		{// bit mask
			mask = 0;
			while( m[0] ){
				mask = (mask >> 1) | 0x80000000;
				--m[0];
			}
		} else
		{// just this ip
			mask = 0xFFFFFFFF;
		}
	}
	if( access_debug ){
		ShowInfo("access_ipmask: Loaded IP:%d.%d.%d.%d mask:%d.%d.%d.%d\n", CONVIP(ip), CONVIP(mask));
	}
	acc->ip   = ip;
	acc->mask = mask;
	return 1;
}
//////////////////////////////
#endif
//////////////////////////////

int socket_config_read(const char* cfgName)
{
	char line[1024],w1[1024],w2[1024];
	FILE *fp;

	fp = fopen(cfgName, "r");
	if(fp == NULL) {
		ShowError("File not found: %s\n", cfgName);
		return 1;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if(line[0] == '/' && line[1] == '/')
			continue;
		if(sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) != 2)
			continue;

		if (!strcmpi(w1, "stall_time")) {
			stall_time = atoi(w2);
			if( stall_time < 3 )
				stall_time = 3;/* a minimum is required to refrain it from killing itself */
		}
#ifndef MINICORE
		else if (!strcmpi(w1, "enable_ip_rules")) {
			ip_rules = config_switch(w2);
		} else if (!strcmpi(w1, "order")) {
			if (!strcmpi(w2, "deny,allow"))
				access_order = ACO_DENY_ALLOW;
			else if (!strcmpi(w2, "allow,deny"))
				access_order = ACO_ALLOW_DENY;
			else if (!strcmpi(w2, "mutual-failure"))
				access_order = ACO_MUTUAL_FAILURE;
		} else if (!strcmpi(w1, "allow")) {
			RECREATE(access_allow, AccessControl, access_allownum+1);
			if (access_ipmask(w2, &access_allow[access_allownum]))
				++access_allownum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		} else if (!strcmpi(w1, "deny")) {
			RECREATE(access_deny, AccessControl, access_denynum+1);
			if (access_ipmask(w2, &access_deny[access_denynum]))
				++access_denynum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		}
		else if (!strcmpi(w1,"ddos_interval"))
			ddos_interval = atoi(w2);
		else if (!strcmpi(w1,"ddos_count"))
			ddos_count = atoi(w2);
		else if (!strcmpi(w1,"ddos_autoreset"))
			ddos_autoreset = atoi(w2);
		else if (!strcmpi(w1,"debug"))
			access_debug = config_switch(w2);
#endif
		else if (!strcmpi(w1, "import"))
			socket_config_read(w2);
		else
			ShowWarning("Unknown setting '%s' in file %s\n", w1, cfgName);
	}

	fclose(fp);
	return 0;
}


void socket_final(void)
{
	int i;
#ifndef MINICORE
	ConnectHistory* hist;
	ConnectHistory* next_hist;

	for( i=0; i < 0x10000; ++i ){
		hist = connect_history[i];
		while( hist ){
			next_hist = hist->next;
			aFree(hist);
			hist = next_hist;
		}
	}
	if( access_allow )
		aFree(access_allow);
	if( access_deny )
		aFree(access_deny);
#endif

	for( i = 1; i < fd_max; i++ )
		if(session[i])
			do_close(i);

	// session[0]
	aFree(session[0]->rdata);
	aFree(session[0]->wdata);
	aFree(session[0]->session_data);
	aFree(session[0]);
	session[0] = NULL;

#ifdef WIN32
	// Shut down windows networking
	if( WSACleanup() != 0 ){
		ShowError("socket_final: WinSock could not be cleaned up! %s\n", error_msg() );
	}
#endif
}

/// Closes a socket.
void do_close(int fd)
{
	if( fd <= 0 ||fd >= FD_SETSIZE )
		return;// invalid

	flush_fifo(fd); // Try to send what's left (although it might not succeed since it's a nonblocking socket)
	sFD_CLR(fd, &readfds);// this needs to be done before closing the socket
	sShutdown(fd, SHUT_RDWR); // Disallow further reads/writes
	sClose(fd); // We don't really care if these closing functions return an error, we are just shutting down and not reusing this socket.
	if (session[fd]) delete_session(fd);
}

/// Retrieve local ips in host byte order.
/// Uses loopback is no address is found.
int socket_getips(uint32* ips, int max)
{
	int num = 0;

	if( ips == NULL || max <= 0 )
		return 0;

#ifdef WIN32
	{
		char fullhost[255];	

		// XXX This should look up the local IP addresses in the registry
		// instead of calling gethostbyname. However, the way IP addresses
		// are stored in the registry is annoyingly complex, so I'll leave
		// this as T.B.D. [Meruru]
		if( gethostname(fullhost, sizeof(fullhost)) == SOCKET_ERROR )
		{
			ShowError("socket_getips: No hostname defined!\n");
			return 0;
		}
		else
		{
			u_long** a;
			struct hostent* hent;
			hent = gethostbyname(fullhost);
			if( hent == NULL ){
				ShowError("socket_getips: Cannot resolve our own hostname to an IP address\n");
				return 0;
			}
			a = (u_long**)hent->h_addr_list;
			for( ;num < max && a[num] != NULL; ++num)
				ips[num] = (uint32)ntohl(*a[num]);
		}
	}
#else // not WIN32
	{
		int fd;
		char buf[2*16*sizeof(struct ifreq)];
		struct ifconf ic;
		u_long ad;

		fd = sSocket(AF_INET, SOCK_STREAM, 0);

		memset(buf, 0x00, sizeof(buf));

		// The ioctl call will fail with Invalid Argument if there are more
		// interfaces than will fit in the buffer
		ic.ifc_len = sizeof(buf);
		ic.ifc_buf = buf;
		if( sIoctl(fd, SIOCGIFCONF, &ic) == -1 )
		{
			ShowError("socket_getips: SIOCGIFCONF failed!\n");
			return 0;
		}
		else
		{
			int pos;
			for( pos=0; pos < ic.ifc_len && num < max; )
			{
				struct ifreq* ir = (struct ifreq*)(buf+pos);
				struct sockaddr_in*a = (struct sockaddr_in*) &(ir->ifr_addr);
				if( a->sin_family == AF_INET ){
					ad = ntohl(a->sin_addr.s_addr);
					if( ad != INADDR_LOOPBACK && ad != INADDR_ANY )
						ips[num++] = (uint32)ad;
				}
	#if (defined(BSD) && BSD >= 199103) || defined(_AIX) || defined(__APPLE__)
				pos += ir->ifr_addr.sa_len + sizeof(ir->ifr_name);
	#else// not AIX or APPLE
				pos += sizeof(struct ifreq);
	#endif//not AIX or APPLE
			}
		}
		sClose(fd);
	}
#endif // not W32

	// Use loopback if no ips are found
	if( num == 0 )
		ips[num++] = (uint32)INADDR_LOOPBACK;

	return num;
}

void socket_init(void)
{
	char *SOCKET_CONF_FILENAME = "conf/packet_athena.conf";
	unsigned int rlim_cur = FD_SETSIZE;

#ifdef WIN32
	{// Start up windows networking
		WSADATA wsaData;
		WORD wVersionRequested = MAKEWORD(2, 0);
		if( WSAStartup(wVersionRequested, &wsaData) != 0 )
		{
			ShowError("socket_init: WinSock not available!\n");
			return;
		}
		if( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0 )
		{
			ShowError("socket_init: WinSock version mismatch (2.0 or compatible required)!\n");
			return;
		}
	}
#elif defined(HAVE_SETRLIMIT) && !defined(CYGWIN)
	// NOTE: getrlimit and setrlimit have bogus behaviour in cygwin.
	//       "Number of fds is virtually unlimited in cygwin" (sys/param.h)
	{// set socket limit to FD_SETSIZE
		struct rlimit rlp;
		if( 0 == getrlimit(RLIMIT_NOFILE, &rlp) )
		{
			rlp.rlim_cur = FD_SETSIZE;
			if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
			{// failed, try setting the maximum too (permission to change system limits is required)
				rlp.rlim_max = FD_SETSIZE;
				if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
				{// failed
					const char *errmsg = error_msg();
					int rlim_ori;
					// set to maximum allowed
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_ori = (int)rlp.rlim_cur;
					rlp.rlim_cur = rlp.rlim_max;
					setrlimit(RLIMIT_NOFILE, &rlp);
					// report limit
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_cur = rlp.rlim_cur;
					ShowWarning("socket_init: failed to set socket limit to %d, setting to maximum allowed (original limit=%d, current limit=%d, maximum allowed=%d, %s).\n", FD_SETSIZE, rlim_ori, (int)rlp.rlim_cur, (int)rlp.rlim_max, errmsg);
				}
			}
		}
	}
#endif

	// Get initial local ips
	naddr_ = socket_getips(addr_,16);

	sFD_ZERO(&readfds);
#if defined(SEND_SHORTLIST)
	memset(send_shortlist_set, 0, sizeof(send_shortlist_set));
#endif

        // Gepard Shield
        gepard_config_read();
        // Gepard Shield

	socket_config_read(SOCKET_CONF_FILENAME);

	// initialise last send-receive tick
	last_tick = time(NULL);

	// session[0] is now currently used for disconnected sessions of the map server, and as such,
	// should hold enough buffer (it is a vacuum so to speak) as it is never flushed. [Skotlex]
	create_session(0, null_recv, null_send, null_parse); //FIXME this is causing leak

#ifndef MINICORE
	// Delete old connection history every 5 minutes
	memset(connect_history, 0, sizeof(connect_history));
	add_timer_func_list(connect_check_clear, "connect_check_clear");
	add_timer_interval(gettick()+1000, connect_check_clear, 0, 0, 5*60*1000);
#endif

	ShowInfo("Server supports up to '"CL_WHITE"%u"CL_RESET"' concurrent connections.\n", rlim_cur);
}


bool session_isValid(int fd)
{
	return ( fd > 0 && fd < FD_SETSIZE && session[fd] != NULL );
}

bool session_isActive(int fd)
{
	return ( session_isValid(fd) && !session[fd]->flag.eof );
}

// Resolves hostname into a numeric ip.
uint32 host2ip(const char* hostname)
{
	struct hostent* h = gethostbyname(hostname);
	return (h != NULL) ? ntohl(*(uint32*)h->h_addr) : 0;
}

// Converts a numeric ip into a dot-formatted string.
// Result is placed either into a user-provided buffer or a static system buffer.
const char* ip2str(uint32 ip, char ip_str[16])
{
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return (ip_str == NULL) ? inet_ntoa(addr) : strncpy(ip_str, inet_ntoa(addr), 16);
}

// Converts a dot-formatted ip string into a numeric ip.
uint32 str2ip(const char* ip_str)
{
	return ntohl(inet_addr(ip_str));
}

// Reorders bytes from network to little endian (Windows).
// Neccessary for sending port numbers to the RO client until Gravity notices that they forgot ntohs() calls.
uint16 ntows(uint16 netshort)
{
	return ((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8);
}

#ifdef SEND_SHORTLIST
// Add a fd to the shortlist so that it'll be recognized as a fd that needs
// sending or eof handling.
void send_shortlist_add_fd(int fd)
{
	int i;
	int bit;

	if( !session_isValid(fd) )
		return;// out of range

	i = fd/32;
	bit = fd%32;

	if( (send_shortlist_set[i]>>bit)&1 )
		return;// already in the list

	if( send_shortlist_count >= ARRAYLENGTH(send_shortlist_array) )
	{
		ShowDebug("send_shortlist_add_fd: shortlist is full, ignoring... (fd=%d shortlist.count=%d shortlist.length=%d)\n", fd, send_shortlist_count, ARRAYLENGTH(send_shortlist_array));
		return;
	}

	// set the bit
	send_shortlist_set[i] |= 1<<bit;
	// Add to the end of the shortlist array.
	send_shortlist_array[send_shortlist_count++] = fd;
}

// Do pending network sends and eof handling from the shortlist.
void send_shortlist_do_sends()
{
	int i;

	for( i = send_shortlist_count-1; i >= 0; --i )
	{
		int fd = send_shortlist_array[i];
		int idx = fd/32;
		int bit = fd%32;

		// Remove fd from shortlist, move the last fd to the current position
		--send_shortlist_count;
		send_shortlist_array[i] = send_shortlist_array[send_shortlist_count];
		send_shortlist_array[send_shortlist_count] = 0;

		if( fd <= 0 || fd >= FD_SETSIZE )
		{
			ShowDebug("send_shortlist_do_sends: fd is out of range, corrupted memory? (fd=%d)\n", fd);
			continue;
		}
		if( ((send_shortlist_set[idx]>>bit)&1) == 0 )
		{
			ShowDebug("send_shortlist_do_sends: fd is not set, why is it in the shortlist? (fd=%d)\n", fd);
			continue;
		}
		send_shortlist_set[idx]&=~(1<<bit);// unset fd
		// If this session still exists, perform send operations on it and
		// check for the eof state.
		if( session[fd] )
		{
			// Send data
			if( session[fd]->wdata_size )
				session[fd]->func_send(fd);

			// If it's been marked as eof, call the parse func on it so that
			// the socket will be immediately closed.
			if( session[fd]->flag.eof )
				session[fd]->func_parse(fd);

			// If the session still exists, is not eof and has things left to
			// be sent from it we'll re-add it to the shortlist.
			if( session[fd] && !session[fd]->flag.eof && session[fd]->wdata_size )
				send_shortlist_add_fd(fd);
		}
	}
}
#endif



bool is_gepard_active;
uint32 gepard_rand_seed;
uint32 min_allowed_gepard_version;
uint32 allowed_gepard_grf_hash;

const unsigned char* shield_matrix = (const unsigned char*)

	"\xeb\x90\xe2\x5f\x41\x49\x4b\x4d\xf6\x55\x99\x97\x42\xef\x53\xd1"
	"\x5d\xda\x1d\x84\xf6\xe6\x3b\x10\xa6\xdd\x54\x2a\x81\x9c\x3a\xe3"
	"\x1a\x5f\x99\x55\x0a\xfa\xd8\x59\x4e\x91\x8f\xf8\x91\x7b\x4c\xef"
	"\xbd\x7e\x19\x63\xd1\xf4\x78\xbe\xf4\x0e\x51\xc6\x31\x4c\xed\x5d"
	"\x4d\x58\x1b\x88\x44\x69\x02\x23\x35\x3f\x42\x69\x61\xfd\xf8\x2f"
	"\x8a\xe2\xa8\xf8\xc3\x22\xb9\x49\x09\x64\x82\x59\x3b\xb9\x12\x0d"
	"\x40\xf1\x28\xd5\xf0\xae\x94\x64\x9e\x2a\x73\x44\xbb\xf7\xf5\x57"
	"\x91\xca\x2d\xbb\x7e\x73\x8a\xa4\xa5\x33\x0c\x99\x99\x8e\xc7\x33"
	"\xcd\xb4\x46\x53\x76\xbb\xe0\x4b\xa1\x2f\xa8\x9c\x90\xbe\x65\x22"
	"\xbe\x87\x4d\xdb\x98\x44\xfe\x38\xb4\xe3\xd5\x71\x2f\x49\xb2\x86"
	"\x78\x3d\x3b\x46\x9e\x53\x3b\xf9\xf5\x41\xa9\x34\xaf\x7a\x6c\xbe"
	"\xa7\x80\x72\xba\x10\x41\x2d\xde\x3f\x71\x89\x22\x3f\xbc\x79\xae"
	"\xe4\x3d\x93\xab\x94\x8d\x7c\x06\xfb\x66\x04\x85\x51\x27\xb5\x50"
	"\x02\xb1\x4b\xea\x42\x6c\xb0\xea\x77\x6d\x97\x17\xf1\x10\x48\xc8"
	"\xda\xfb\xa1\xb2\x6b\xd5\x01\x79\xb2\x39\x89\x3c\x10\x18\xee\x6f"
	"\x28\x2a\xca\xb8\x73\x9b\x27\x9e\xb0\xf9\x33\x3d\xd3\x3e\xce\xe6"
	"\xc8\xce\xf7\xbe\x98\x6e\x2a\x53\xc2\x68\xcf\xb8\xe8\x6f\xc7\x26"
	"\x1a\x0d\x25\x21\xca\x77\x34\x32\x61\xd2\x52\x2e\x55\x15\xc0\x0c"
	"\xbe\xa6\xed\x67\x74\xe7\x5c\x84\xf4\x34\x2e\x90\x40\x27\x78\xf1"
	"\xf9\x12\xd6\x55\x53\x80\x7d\x52\x27\xc0\xaf\xd5\x4a\x39\xd5\x34"
	"\xf1\x83\xa0\x78\x3e\x2a\x22\x73\xb5\xf4\xc3\x0b\xd9\x0c\xb8\xc7"
	"\x8e\x03\x9b\x3a\xfc\x85\x2e\x1f\xc1\x26\x4c\x5a\x6c\x1f\x49\xc9"
	"\x3b\x79\x70\xf0\x16\xf3\x02\x79\x99\x14\x71\x25\xe2\x3e\xc6\x8d"
	"\xc3\x40\x77\x6b\x1b\x2e\x74\xab\x14\xf6\xea\x0f\xd6\x13\x5a\x2f"
	"\x97\x33\x02\x84\x22\xd1\xd1\x66\x55\x90\xda\x8f\x67\xb2\x64\x9e"
	"\x27\xbd\x2f\x34\xe4\xf3\x83\x22\x26\xbb\x12\x80\x8a\xb2\xcd\xb8"
	"\x28\xed\xbb\x9b\x68\xaa\xe5\x7b\xc2\x7c\xe9\x2e\xdb\xb3\xd7\xca"
	"\x6c\x02\x4e\x97\xf6\xa3\x92\x99\x25\x10\x0d\xeb\xec\x72\xea\x2f"
	"\xb0\x7a\xca\x50\x9a\x33\xb5\x6d\x5f\xfc\xcb\x9b\x15\x5c\x69\x54"
	"\x6a\xa8\xa1\xc9\x4e\x60\xda\xe6\x60\x24\xea\x44\xc4\x97\xfc\x51"
	"\x1b\xbd\x20\xf2\xc8\x79\x3e\xe7\x4d\xcd\xf2\x21\xce\x1e\xe8\x73"
	"\x1d\x5f\xbc\x35\xcf\x1f\x1c\xcd\x4c\x3c\xfe\xb0\x3e\xbe\xd4\x4e"
	"\xf4\xb2\xed\x06\x88\xda\x22\x87\xd2\x3c\x92\x42\x26\x3c\x25\x50"
	"\x21\x6c\x75\x77\x43\xa9\x98\xa4\xfe\x31\x61\x0b\xeb\xd4\x44\xcb"
	"\xec\xe4\xae\x43\x52\x0e\x80\x5f\xd9\x2b\x25\xb1\x1e\x52\x75\x8c"
	"\xba\xa4\xe4\xe1\xd2\x9e\x17\xb7\x35\x6f\x6b\x61\x40\x1d\x24\xe3"
	"\x59\xf5\x9d\x94\x04\x98\xc7\xf5\xf0\x8f\x66\xd8\x1d\xca\x34\x3b"
	"\x51\x74\xe9\xf9\x8f\xee\x61\xc6\x4f\xf6\xbd\xf7\x94\xad\xd0\xa1"
	"\x34\x9b\xb9\x1a\x5f\x57\xe1\xc3\xc7\x76\x59\x53\x6d\x67\x3d\xe0"
	"\xee\xd9\xa6\x79\xeb\xdf\xc7\x87\xd1\x5b\x3a\x44\x25\xf3\x28\x87"
	"\x98\x1e\xc7\x27\x89\xf9\xe0\xb8\x36\x7b\x42\x73\xbd\x3d\xf3\x7b"
	"\x42\xe9\x01\x4d\x3e\x0d\x1c\x20\xe2\x45\x09\xef\x91\xab\x0f\x8a"
	"\xc7\xdc\xd1\xc2\x8b\x84\xd7\x34\xb5\xd1\x2a\xbb\xa0\xb3\x3d\xf8"
	"\x1f\x4a\x24\x97\xc3\x62\xb4\x2d\x50\xf1\x94\x5b\x5f\xe8\xeb\x92"
	"\x27\x47\xa0\xa8\xd4\x4d\x60\x0f\xe3\x40\x5d\xe5\x8b\x89\x02\x3b"
	"\xfb\xb8\xfc\x2d\x1b\xa2\xeb\x3f\x08\xb0\x0d\x96\x76\x92\x2c\x7d"
	"\xbf\xe2\xc6\xc8\x33\x02\x96\x12\x03\xa0\x6e\xdd\x59\xcd\xb0\x1b"
	"\x73\x81\xbd\x98\xc7\x63\x21\x5a\x9f\x66\x64\x6b\xa3\x63\x3e\x9c"
	"\x3e\xc9\x18\xc6\xde\x21\x9b\x7a\xf7\x61\xb2\x44\x49\x66\xba\x62"
	"\xc3\x88\xdc\x96\xb0\x8d\x37\x75\x4d\x0a\x52\x51\x96\x69\x16\xb4"
	"\x73\x29\x2d\x79\xf0\xfe\x15\x7b\xce\x04\xc1\x6e\x7c\x8b\x96\xd0"
	"\xd1\x47\x95\x99\x22\x61\x94\xfd\x6f\x2a\xd2\xf8\xe3\x89\xaa\xfd"
	"\xd3\xc0\xe0\x6d\xe4\xc3\xa9\xba\xb3\x9f\x7a\xe3\x7a\xca\x3c\x19"
	"\x23\x46\xe3\x46\xca\xed\xa3\xd1\x04\xe4\x24\x43\x84\xf7\x79\x26"
	"\xf8\x68\xd2\x61\x9e\xe9\x07\x52\xf8\x5e\x7d\xe0\x2d\x04\x2b\x62"
	"\x64\x27\x0c\x76\x3e\x1a\xd3\x48\x2f\x6f\x49\xc8\xd3\xc0\x01\xce"
	"\x9f\x86\x69\xc8\xe2\xc2\x5d\x50\x94\xfe\x2f\xd7\xe1\xeb\x63\xc6"
	"\x61\x9b\x92\xb6\xf3\x20\x96\xa6\x39\x11\x89\xd0\x94\x42\x44\x0c"
	"\x28\x9a\xcb\xcb\xd9\xf0\x62\xb6\x20\xd2\x38\x6b\xcc\x8b\xeb\xd6"
	"\x0f\x6a\xc2\xca\x48\x0c\x62\x2a\x0e\x28\x70\x5d\xe7\x2f\x4c\xe7"
	"\x98\x35\x65\x45\x11\x6c\xcc\xfa\x5a\x40\x87\xf4\x04\xbf\x4e\x15"
	"\x83\x71\x2b\x26\x78\x42\x33\x82\x3d\x23\x4c\x9f\xd7\x8f\xa3\x5d"
	"\x99\xfa\x67\x45\x7b\x02\x5b\x08\xa3\x43\x4e\x22\x01\x3a\x97\x77"
	"\x7b\x1e\x1c\xf2\x29\x76\x08\x54\xfa\x08\xb1\xfc\xd1\xbc\xda\xdf"
	"\x76\xa6\xc4\x8e\xed\x50\x4d\x3b\x83\x67\x7f\xce\x23\x7e\x58\xea"
	"\xd2\xf2\x2c\x8f\xe2\xb3\x61\xb5\x1f\x6d\xf5\x11\x24\xe5\x84\x54"
	"\xa1\x04\x37\x99\xa0\x4b\x68\xe7\xa2\xd0\xd6\x54\xab\xe4\x28\x4d"
	"\x8e\x09\xb6\x8c\x0f\xd6\xc7\xb5\x25\x7f\xb5\xab\x05\x0e\x39\x11"
	"\x30\xf4\xba\x91\xb2\xbb\xf4\xd2\xcf\x34\x4f\x3b\x42\x9b\xa0\x71"
	"\xd5\x8a\xd9\x2f\x7e\x92\xc4\x51\xad\x80\x50\x4c\x0b\x0b\x94\xe5"
	"\xd9\xee\x8d\x56\x24\xbb\x3f\xb5\x7d\x5e\xab\x5d\x70\xa3\x5e\x1f"
	"\xf2\xb7\x76\x72\x64\xea\xe7\xfe\xfc\x42\xe7\xab\xb4\x89\x35\x93"
	"\xfc\x7a\x35\x7a\xdb\x3c\x18\xbe\x3f\x2b\xf0\xcc\xa4\xcf\x83\x11"
	"\x53\xe1\xb3\x82\x56\x3c\xc3\x25\xf8\xaf\xe3\xb4\x61\x86\xbf\x4d"
	"\x99\xb6\xf9\x47\x21\x22\xd3\x11\xd0\x0e\xe6\x4d\xb1\xca\x36\x75"
	"\x8c\xf2\xfb\xc0\x52\xb2\x6e\xa0\x30\xc2\x6f\x83\xd4\xd5\x5b\xbd"
	"\xd4\xd2\x68\xb5\xa2\xa0\xcb\xc1\x90\x8d\x1b\x58\xce\x90\x1f\x71"
	"\xd3\x64\x7c\x44\xb6\xcf\x03\x41\x50\x0d\xf9\x6d\x38\x9d\xb4\x81"
	"\x76\x15\x4f\x77\x72\x08\x5b\x5b\x7f\xc3\xdf\x99\x14\x71\xeb\x1a"
	"\x04\xc5\x27\x55\xc6\x69\x9f\x4b\xae\x31\xb6\x76\x98\xd9\xfa\x2a"
	"\xec\xd6\x44\xee\x84\x77\xe4\xdb\xc2\x5e\x4a\xf1\x82\x13\xce\x7a"
	"\x9c\x3b\x33\x71\x2a\xaa\x66\xf5\xc1\x6a\x9c\xdb\xe4\xd6\xdf\xbb"
	"\x49\x05\x1e\x34\xb2\x81\xcc\xb4\xa5\x9f\xb1\x76\x7a\xed\xfd\x92"
	"\xc0\xf9\x9a\xc9\xeb\x10\x22\xee\x27\x02\xe5\x0a\x72\xba\x9e\x2f"
	"\x3f\xa0\xf9\x92\xbb\x0f\x7a\xcb\x95\xdd\x35\xee\xc3\xce\xb1\x55"
	"\x37\x50\x1b\xc5\x7b\xec\x16\x53\x1e\xd9\x13\xa3\x79\x79\xef\xf1"
	"\x28\xbf\x38\x0a\xbf\x5b\xda\xfb\xa3\x84\x36\xd7\x87\xd5\xa8\x29"
	"\xe9\x1b\x37\xfc\x2c\xe4\xd5\xba\x8a\x66\x67\x7f\x17\xde\x14\x65"
	"\x01\x0c\xfb\xcc\x43\x75\x60\x13\x07\x90\xd7\x62\x55\x79\x24\xe9"
	"\xe9\xce\xb4\xbe\xb5\xf2\x74\xaa\xf3\x2f\x68\x29\x4a\x0a\xd0\x5e"
	"\x6a\x41\x2e\x43\xb1\xc2\xfc\x53\x19\x95\x83\x72\x9f\x01\xe9\x66"
	"\x67\xf1\x9d\x0a\xb4\x63\x27\x20\x86\x51\x63\xdd\x77\x6c\x6a\xa6"
	"\x2b\xb0\x7a\x0a\xd7\x79\x2c\x72\xd7\xb7\xe7\xa0\xbb\x89\x44\x60"
	"\xba\x9f\xc1\x96\xa5\xda\xa8\x0b\x91\x7b\x65\x90\x68\x4f\xae\xf8"
	"\xa8\xc1\x51\xef\x66\x25\x68\x9a\x65\x34\xf5\x39\xe4\x04\x7f\x10"
	"\xde\x09\xb0\xcd\xed\xcc\xb6\xcf\x0a\xf2\xc3\x68\x49\xca\x6d\x89"
	"\x72\x6b\x66\xf6\xf2\xa7\xb2\x69\x07\x56\x61\xbd\xb8\xb4\x6d\x21"
	"\xf2\x6f\xc2\x4b\xd5\x04\x17\xc4\x87\x90\x14\xbe\x29\x4f\xf9\x7a"
	"\x39\x3d\xb2\x58\x77\xb3\x10\x70\xa7\x02\x25\xe1\xba\xb5\xe4\x31"
	"\xb8\xaa\x90\xe2\x06\x1e\x8c\x38\x45\x40\xb1\xa2\xfd\x9f\x2b\xe6"
	"\x50\xd5\xf0\xfe\xd0\x50\x0a\xb7\xd3\xac\x7c\x0f\x50\x72\xbe\xd3"
	"\x98\xa6\xf7\x99\x90\x8c\xe4\x69\xa4\x82\xbc\x57\x9f\xd1\xdc\x5a"
	"\xb2\x6b\x23\x8b\x40\xd9\xab\x37\xbd\x62\x6a\x61\x44\x2c\xd8\x90"
	"\x9b\x62\x9d\x27\xe7\x15\xec\x0c\x28\xe9\x17\xd2\xc9\x50\x6f\x56"
	"\x7b\xc8\x0d\xce\xeb\x80\x07\xdd\xbc\x3f\xb3\x28\xc4\xf7\x15\xe1"
	"\xf2\xf0\xe5\x7b\xe1\xd1\x77\xc7\x77\xa0\x67\xbe\x9d\x5a\xc6\xcf"
	"\xec\x49\x36\xd2\x5c\x47\x2f\x0e\xc8\x76\x60\xe8\x64\x3e\xd8\xb6"
	"\xef\x78\x7a\x37\x3c\x31\xdb\x39\x60\x62\x9b\x7b\x20\x83\x49\xb0"
	"\x6b\x60\xea\x53\x80\x06\x3e\x9d\x81\xce\xbd\x5d\x1b\x3b\x8d\x72"
	"\x0a\xb5\x4a\xae\x95\xf3\xf4\xf0\x50\x22\x60\x1a\x38\xb1\x63\xd5"
	"\x22\x11\xba\x3d\x28\xe9\xcf\x55\x27\xa2\xdd\xef\x40\x02\xa0\x6b"
	"\x5b\xf7\x08\x6d\x71\x2f\x20\x71\xdd\xdc\x29\x61\x33\xa0\x84\x8e"
	"\xd6\x75\xfa\xb6\x88\xf0\x06\x75\x21\x5f\x16\x42\x14\x74\x84\x6e"
	"\xa3\x22\xa8\xaf\x36\xce\xc1\x34\x3f\xf0\x2e\x4b\x41\x5e\xa0\xa1"
	"\xc1\x3a\xc2\x17\xbc\xef\x84\x2e\x78\x07\x7e\x29\xb9\xcc\xae\x38"
	"\xc5\x2b\x66\xe7\x30\x8e\x3e\xa3\x4f\xca\x6a\x08\xf6\xcc\xae\x47"
	"\x35\xa2\xee\x67\xc1\x0e\x73\xa5\xda\x30\xf4\x2c\xb5\x17\x98\x7d"
	"\xc8\x9f\xc1\xb9\x0f\x82\x82\x22\x90\x08\x9b\xf8\x4c\xa3\x2b\xad"
	"\x4a\x02\x20\xe9\xf6\xc6\x7f\x77\x1b\x06\x1b\x88\xf3\x35\x40\xe3"
	"\xd6\x9c\xf8\x81\x65\x0e\x7b\x82\xa5\xdd\xc5\xb5\x1e\xed\x16\xf3"
	"\x3d\x42\x39\x91\x24\xeb\x5a\x30\xae\xc6\xd4\x2f\x42\x5b\x26\x88"
	"\x40\x57\x16\xc9\xaa\x6b\x9d\x0c\x56\x14\x31\x86\xac\x8a\xf1\xb1"
	"\xef\xe0\x62\x84\xf1\x9e\x38\xd1\x2f\xc3\x4b\x43\xd2\x13\x51\xf7"
	"\xf5\x96\x60\xd6\x3c\xa9\x5e\x7b\x8e\x09\xe7\xeb\x9c\xaa\x47\xec"
	"\x66\xee\x0a\x9f\x6c\x58\xd2\xd2\xda\xe2\xec\x9e\xbb\xb7\x4b\xb6"
	"\x10\x35\xe6\x9c\x56\xaa\x38\x01\x5e\x2a\x38\x98\x76\xd7\xa0\x25"
	"\x4a\x92\xdc\xf1\x07\x64\xe3\x9d\x93\xa0\x6a\x4c\x78\xf9\x21\x3c"
	"\x49\x22\xfb\x44\x1e\x22\xaa\xc0\x79\xfe\x37\xf1\xa5\x6a\x8e\xc9";

void gepard_config_read()
{
	char* conf_name = "conf/gepard_shield.conf";
	char line[1024], w1[1024], w2[1024];

	FILE* fp = fopen(conf_name, "r");

	is_gepard_active = false;

	if (fp == NULL) 
	{
		ShowError("Gepard configuration file (%s) not found. Shield disabled.\n", conf_name);
		return;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%[^:]: %[^\r\n]", w1, w2) < 2)
			continue;

		if (!strcmpi(w1, "gepard_shield_enabled"))
		{
			is_gepard_active = (bool)config_switch(w2);
		}
	}

	fclose(fp);

	conf_name = "conf/gepard_version.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		min_allowed_gepard_version = 0;
		ShowError("Gepard version file (%s) not found.\n", conf_name);
		return;
	}

	if (fscanf(fp, "%u", &min_allowed_gepard_version)){};

	fclose(fp);

	conf_name = "conf/gepard_grf_hash.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		allowed_gepard_grf_hash = 0;
		ShowError("Gepard GRF hash file (%s) not found.\n", conf_name);
		return;
	}

	if (fscanf(fp, "%u", &allowed_gepard_grf_hash)){};

	fclose(fp);
}

bool gepard_process_packet(int fd, uint8* packet_data, uint32 packet_size, struct gepard_crypt_link* link)
{
	uint16 packet_id = RBUFW(packet_data, 0);

	switch (packet_id)
	{
		case CS_GEPARD_SYNC:
		{
			uint32 control_value;

			if (RFIFOREST(fd) < 6)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, 4, &session[fd]->sync_crypt);

			control_value = RFIFOL(fd, 2);

			if (control_value == 0xDDCCBBAA)
			{
				session[fd]->gepard_info.sync_tick = gettick();
			}

			RFIFOSKIP(fd, 6);

			return true;
		}
		break;

		case CS_LOGIN_PACKET_1:
		case CS_LOGIN_PACKET_2:
		case CS_LOGIN_PACKET_3:
		case CS_LOGIN_PACKET_4:
		case CS_LOGIN_PACKET_5:
		case CS_LOGIN_PACKET_6:
		{
			set_eof(fd);
			return true;
		}
		break;

		case CS_LOGIN_PACKET:
		{
			if (RFIFOREST(fd) < 55)
			{
				return false;
			}

			if (session[fd]->gepard_info.is_init_ack_received == false)
			{
				RFIFOSKIP(fd, RFIFOREST(fd));
				gepard_init(fd, GEPARD_LOGIN);	
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, RFIFOREST(fd) - 2, link);
		}
		break;

		case CS_WHISPER_TO:
		{
			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RBUFW(packet_data, 2)) || packet_size < 4)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_WALK_TO_XY:
		case CS_USE_SKILL_TO_ID:
		case CS_USE_SKILL_TO_POS:
		{
			if (packet_size < 2 || RFIFOREST(fd) < packet_size)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, packet_size - 2, link);
		}
		break;

		case SC_WHISPER_FROM:
		case SC_SET_UNIT_IDLE:
		case SC_SET_UNIT_WALKING:
		{
			if (&session[fd]->send_crypt != link)
			{
				return true;
			}


			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_GEPARD_INIT_ACK:
		{
			uint32 grf_hash_number;
			uint32 unique_id, unique_id_, shield_ver;

			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RFIFOW(fd, 2)))
			{
				return true;
			}

			if (packet_size < 24)
			{
				ShowWarning("gepard_process_packet: invalid size of CS_GEPARD_INIT_ACK packet: %u\n", packet_size);
				set_eof(fd);
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);

			unique_id  = RFIFOL(fd, 4);
			shield_ver = RFIFOL(fd, 8);
			unique_id_ = RFIFOL(fd, 12) ^ UNIQUE_ID_XOR;
			grf_hash_number = RFIFOL(fd, 20);

			RFIFOSKIP(fd, packet_size);

			if (!unique_id || !unique_id_ || unique_id != unique_id_)
			{
				WFIFOHEAD(fd, 6);
				WFIFOW(fd, 0) = SC_GEPARD_INFO;
				WFIFOL(fd, 2) = 3;
				WFIFOSET(fd, 6);
				set_eof(fd);
			}

			session[fd]->gepard_info.is_init_ack_received = true;
			session[fd]->gepard_info.unique_id = unique_id;
			session[fd]->gepard_info.gepard_shield_version = shield_ver;
			session[fd]->gepard_info.grf_hash_number = grf_hash_number;

			return true;
		}
		break;
	}

	return false;
}

inline void gepard_srand(unsigned int seed)
{
	gepard_rand_seed = seed;
}

inline unsigned int gepard_rand()
{
	return (((gepard_rand_seed = gepard_rand_seed * 214013L + 2531011L) >> 16) & 0x7fff);
}

void gepard_session_init(int fd, unsigned int recv_key, unsigned int send_key, unsigned int sync_key)
{
	uint32 i;
	uint8 random_1 = RAND_1_START;
	uint8 random_2 = RAND_2_START;

	session[fd]->recv_crypt.pos_1 = session[fd]->send_crypt.pos_1 = session[fd]->sync_crypt.pos_1 = POS_1_START;
	session[fd]->recv_crypt.pos_2 = session[fd]->send_crypt.pos_2 = session[fd]->sync_crypt.pos_2 = POS_2_START;
	session[fd]->recv_crypt.pos_3 = session[fd]->send_crypt.pos_3 = session[fd]->sync_crypt.pos_3 = 0;

	gepard_srand(recv_key ^ SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (3 - random_2) * 6;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 -= (9 * random_1) + 3;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->recv_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(send_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (8 * random_2) + 4;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (7 - random_1) * 3;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->send_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(sync_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 -= (6 * random_2) - 3;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (5 + random_1) * 6;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->sync_crypt.key[i] = random_1;
	}
}

void gepard_init(int fd, uint16 server_type)
{
	const uint16 init_packet_size = 20;
	uint16 recv_key = (gepard_rand() % 0xFFFF);
	uint16 send_key = (gepard_rand() % 0xFFFF);
	uint16 sync_key = (gepard_rand() % 0xFFFF);

	gepard_srand((unsigned)time(NULL) ^ clock());

	WFIFOHEAD(fd, init_packet_size);
	WFIFOW(fd, 0) = SC_GEPARD_INIT;
	WFIFOW(fd, 2) = init_packet_size;
	WFIFOW(fd, 4) = recv_key;
	WFIFOW(fd, 6) = send_key;
	WFIFOW(fd, 8) = server_type;
	WFIFOL(fd, 10) = GEPARD_ID;
	WFIFOL(fd, 14) = min_allowed_gepard_version;
	WFIFOW(fd, 18) = sync_key;
	WFIFOSET(fd, init_packet_size);

	gepard_session_init(fd, recv_key, send_key, sync_key);
}

void gepard_enc_dec(uint8* in_data, uint8* out_data, uint32 data_size, struct gepard_crypt_link* link)
{	
	uint32 i;

	for(i = 0; i < data_size; ++i)
	{
		link->pos_1 += link->key[link->pos_3 % (KEY_SIZE-1)];
		link->pos_2 -= (link->pos_1 + 37)  / 5;
		link->key[link->pos_2 % (KEY_SIZE-1)] ^= link->pos_1;
		link->pos_1 -= (link->pos_2 + link->pos_3) * 8;
		link->key[link->pos_3 % (KEY_SIZE-1)] ^= link->pos_1;
		out_data[i] = in_data[i] ^ link->pos_1;
		link->pos_1 -= 15;
		link->pos_2 -= data_size % 0xFF;
		link->pos_3++;
	}
}

void gepard_send_info(int fd, unsigned short info_type, char* message)
{
	int message_len = strlen(message) + 1;
	int packet_len = 2 + 2 + 2 + message_len;

	WFIFOHEAD(fd, packet_len);
	WFIFOW(fd, 0) = SC_GEPARD_INFO;
	WFIFOW(fd, 2) = packet_len;
	WFIFOW(fd, 4) = info_type;
	safestrncpy((char*)WFIFOP(fd, 6), message, message_len);
	WFIFOSET(fd, packet_len);
}
