#ifdef USE_ASYNC
  #include "async.h"
  #include <err.h>
#else
  #include "tcpip.h"
#endif
#include "rpc_engine.h"

//#define DEBUG_NETWORK

//--------------------------------------------------------------------------
void dmsg(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(0, rpc, format, va);
}

void derror(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(-1, rpc, format, va);
}

void dwarning(rpc_engine_t *rpc, const char *format, va_list va)
{
  dvmsg(1, rpc, format, va);
}


//--------------------------------------------------------------------------
rpc_engine_t::~rpc_engine_t()
{
  term_irs();
}

//--------------------------------------------------------------------------
void rpc_engine_t::term_irs()
{
  if ( irs == NULL )
    return;
  term_server_irs(irs);
  irs = NULL;
}

//--------------------------------------------------------------------------
rpc_engine_t::rpc_engine_t(idarpc_stream_t *_irs) : irs(_irs)
{
  poll_debug_events = false;
  has_pending_event = false;
  network_error_code = 0;
  verbose = true;
  is_server = true;
  ioctl_handler = NULL;
}

//--------------------------------------------------------------------------
// returns error code
int rpc_engine_t::send_request(bytevec_t &s)
{
  // if nothing is initialized yet or error occurred, silently fail
  if ( irs == NULL || network_error_code != 0 )
    return -1;

  const uchar *ptr = s.begin();
  ssize_t left = s.size();
  while ( left > 0 )
  {
    ssize_t code = irs_send(irs, ptr, left);
    if ( code == -1 )
    {
      code = irs_error(irs);
      set_broken_connection();
      network_error_code = code;
      warning("irs_send: %s", winerr((int)code));
      return (int)code;
    }
    left -= code;
    ptr += code;
  }
  return 0;
}

//--------------------------------------------------------------------------
// receives a buffer from the network
// this may block if polling is required, then virtual poll_events() is called
int rpc_engine_t::recv_all(void *ptr, int left, bool poll)
{
  ssize_t code;
  while ( true )
  {
    code = 0;
    if ( left <= 0 )
      break;

    // the server needs to wait and poll till events are ready
    if ( is_server )
    {
      if ( poll && poll_debug_events && irs_ready(irs, 0) == 0 )
      {
        code = poll_events(TIMEOUT);
        if ( code != 0 )
          break;
        continue;
      }
    }
    code = irs_recv(irs, ptr, left, is_server ? -1 : RECV_TIMEOUT_PERIOD);
    if ( code <= 0 )
    {
      code = irs_error(irs);
      set_broken_connection();
      if ( code == 0 )
      {
        code = -1; // anything but not success
      }
      else
      {
        network_error_code = code;
        dmsg("irs_recv: %s\n", winerr(uint32(code)));
      }
      break;
    }
    left -= (uint32)code;
    // visual studio 64 does not like simple
    // (char*)ptr += code;
    char *p2 = (char *)ptr;
    p2 += code;
    ptr = p2;
  }
  return code;
}

//-------------------------------------------------------------------------
mon_response_t *rpc_engine_t::recv_response(void)
{
  // if nothing is initialized yet or error occurred, silently fail
  if ( irs == NULL || network_error_code != 0 )
    return NULL;

  mon_response_t p;
  int code = recv_all(&p, sizeof(p), poll_debug_events);
  if ( code != 0 )
    return NULL;

  if (p.stx != 2) {
    dwarning("mon: bad stx: %d", p.stx);
    return nullptr;
  }

  if (p.api_id != 2) {
    dwarning("mon: bad api_id: %d", p.api_id);
    return nullptr;
  }

  auto size = sizeof(mon_response_t) + p.body_length;
  uchar *urp = (uchar *)qalloc(size);
  if ( urp == NULL )
  {
    dwarning("rpc: no local memory");
    return NULL;
  }

  memcpy(urp, &p, sizeof(mon_response_t));
  int left = size - sizeof(mon_response_t);
  uchar *ptr = urp + sizeof(mon_response_t);

  code = recv_all(ptr, left, false);
  if ( code != 0 )
  {
    qfree(urp);
    return NULL;
  }

  mon_response_t *rp = (mon_response_t *)urp;
#ifdef DEBUG_NETWORK
  show_hex(rp, size, "RECV 0x%08X %s %lu bytes:\n",
           rp->request_id,
           get_mon_response_name(rp->response_type),
           size);
#endif
  return rp;
}

//--------------------------------------------------------------------------
// sends a request and waits for a reply
// may occasionally sends another request based on the reply
rpc_packet_t *rpc_engine_t::process_request(bytevec_t &req, int preq_flags)
{
  while ( true )
  {
    if ( !req.empty() )
    {
      int code = send_request(req);
      if ( code != 0 || (preq_flags & PREQ_GET_EVENT) != 0 )
        return NULL;

      rpc_packet_t *rp = (rpc_packet_t *)req.begin();
      if ( rp->code == RPC_ERROR )
        qexit(1); // sent error packet, may die now
    }

    rpc_packet_t *rp = recv_request();
    if ( rp == NULL )
      return NULL;

    switch ( rp->code )
    {
      case RPC_UNK:
        dwarning("rpc: remote did not understand our request");
        goto FAILURE;
      case RPC_MEM:
        dwarning("rpc: no remote memory");
        goto FAILURE;
      case RPC_OK:
        return rp;
    }

    if ( (preq_flags & PREQ_MUST_LOGIN) != 0 )
    {
      lprintf("Exploit packet has been detected\n");
FAILURE:
      qfree(rp);
      return NULL;
    }
    req = perform_request(rp);
    qfree(rp);
  }
}

//--------------------------------------------------------------------------
// processes a request and returns a int32
int rpc_engine_t::process_long(bytevec_t &req)
{
  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
int rpc_engine_t::send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
  bytevec_t req = prepare_rpc_packet(RPC_IOCTL);

  append_dd(req, fn);
  append_dd(req, (uint32)size);
  append_memory(req, buf, size);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int code = extract_long(&answer, end);
  ssize_t outsize = extract_long(&answer, end);

  if ( outsize > 0 && poutbuf != NULL )
  {
    *poutbuf = qalloc(outsize);
    if ( *poutbuf != NULL )
      extract_memory(&answer, end, *poutbuf, outsize);
  }
  if ( poutsize != NULL )
    *poutsize = outsize;
  qfree(rp);
  return code;
}

//--------------------------------------------------------------------------
// process an ioctl request and return the reply packet
int rpc_engine_t::handle_ioctl_packet(bytevec_t &req, const uchar *ptr, const uchar *end)
{
  if ( ioctl_handler == NULL )
    return RPC_UNK;

  char *buf = NULL;
  int fn = extract_long(&ptr, end);
  size_t size = extract_long(&ptr, end);
  if ( size > 0 )
  {
    buf = (char *)qalloc(size);
    if ( buf == NULL )
      return RPC_MEM;
  }
  extract_memory(&ptr, end, buf, size);
  void *outbuf = NULL;
  ssize_t outsize = 0;
  int code = ioctl_handler(this, fn, buf, size, &outbuf, &outsize);
  qfree(buf);
  append_dd(req, code);
  append_dd(req, (uint32)outsize);
  if ( outsize > 0 )
    append_memory(req, outbuf, outsize);
  qfree(outbuf);
//  verb(("ioctl(%d) => %d\n", fn, code));
  return RPC_OK;
}


