#include "rpc_debmod.h"
#include <segment.hpp>
#include <err.h>

//--------------------------------------------------------------------------
rpc_debmod_t::rpc_debmod_t(const char *default_platform)
  : rpc_client_t(NULL),
    is_process_running(false),
    resume_mode(RESMOD_NONE),
    current_request_id(1 + arc4random_uniform(0xF0000000))
{
  nregs = debugger.registers_size;
  for ( int i=0; i < nregs; i++ )
  {
    const register_info_t &ri = debugger.registers(i);
    if ( (ri.flags & REGISTER_SP) != 0 )
      sp_idx = i;
    if ( (ri.flags & REGISTER_IP) != 0 )
      pc_idx = i;
  }
  bpt_code.append(debugger.bpt_bytes, debugger.bpt_size);
  rpc = this;

  set_platform(default_platform);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::handle_ioctl(    //-V524 equivalent to 'send_ioctl'
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  return rpc_engine_t::send_ioctl(fn, buf, size, poutbuf, poutsize);
}

//--------------------------------------------------------------------------
inline int get_expected_addrsize(void)
{
  if ( is_miniidb() )
#ifdef __EA64__
    return 8;
#else
    return 4;
#endif
  return inf.is_64bit() ? 8 : 4;
}

//--------------------------------------------------------------------------
uint32 rpc_debmod_t::_send_cmd(BinaryMonitorCommand command, const bytevec_t& body) {
  mon_request_t req;
  req.stx = 2;
  req.api_id = 2;
  req.body_length = body.size();
  req.request_id = current_request_id++;
  req.command = command;
  auto bytes = bytevec_t((char *)&req, sizeof(req));
  bytes.insert(bytes.end(), body.begin(), body.end());
#ifdef DEBUG_NETWORK
  show_hex(bytes.begin(), bytes.size(), "SEND 0x%08X %s %zu bytes:\n",
           req.request_id,
           get_mon_command_name(req.command),
           bytes.size());
#endif
  send_request(bytes);
  return req.request_id;
}

uint32 rpc_debmod_t::cmd_query_registers(BinaryMonitorMemSpace bankId) {
  struct PACKED { BinaryMonitorMemSpace memspace; } body = { bankId };
  return _send_cmd(MON_CMD_REGISTERS_AVAILABLE, bytevec_t(&body, sizeof(body)));
}

uint32 rpc_debmod_t::cmd_load(const char *path, bool run_after_loading, uint16 file_index) {
  bytevec_t body;
  body.push_back(run_after_loading);
  body.push_back(file_index & 0xFF);
  body.push_back(file_index >> 8);
  body.push_back(strlen(path));
  body.insert(body.end(), path, path + strlen(path));
  return _send_cmd(MON_CMD_AUTOSTART, body);
}

uint32 rpc_debmod_t::cmd_reset(BinaryMonitorResetType reset_type) {
  bytevec_t body;
  body.push_back(reset_type);
  return _send_cmd(MON_CMD_RESET, body);
}

uint32 rpc_debmod_t::cmd_set_checkpoint(uint16 saddr, uint16 eaddr, bool is_breakpoint, bool is_enabled, uint8 cpu_operation, bool is_temporary, BinaryMonitorMemSpace memspace) {
  uint8 buf[9];
  *((uint16 *)buf) = saddr;
  *((uint16 *)(buf + 2)) = eaddr;
  buf[4] = is_breakpoint;
  buf[5] = is_enabled;
  buf[6] = cpu_operation;
  buf[7] = is_temporary;
  buf[8] = memspace;
  return _send_cmd(MON_CMD_CHECKPOINT_SET, bytevec_t(buf, 9));
}

uint32 rpc_debmod_t::cmd_delete_checkpoint(uint32 checkpoint_number) {
  return _send_cmd(MON_CMD_CHECKPOINT_DELETE, bytevec_t(&checkpoint_number, 4));
}

uint32 rpc_debmod_t::cmd_get_registers(uint8 memspace = kMemSpaceMainMemory) {
  return _send_cmd(MON_CMD_REGISTERS_GET, bytevec_t(&memspace, 1));
}

uint32 rpc_debmod_t::cmd_advance_instructions(bool step_over, uint16 instruction_count) {
  uint8 buf[3];
  buf[0] = step_over;
  *((uint16 *)(buf + 1)) = instruction_count;
  return _send_cmd(MON_CMD_ADVANCE_INSTRUCTIONS, bytevec_t(buf, 3));
}

uint32 rpc_debmod_t::cmd_memory_get(uint16 saddr, uint16 eaddr, const char *bank, uint8 memspace, bool side_effects) {
  auto it = bank_map.find(bank);
  uint16 bank_id = it == bank_map.end() ? 0 : it->second;
  struct PACKED {
    bool side_effects;
    uint16 start_address;
    uint16 end_address;
    uint8 memspace;
    uint16 bank_id;
  } body = { side_effects, saddr, eaddr, memspace, bank_id };
  return _send_cmd(MON_CMD_MEM_GET, bytevec_t(&body, sizeof(body)));
}

void rpc_debmod_t::process_vice_info(uchar *body) {
  qstring version;
  for (auto len = *body++; len; len--) {
    if (!version.empty())
      version.append('.');
    version.append(*body++ + 0x30);
  }
  vice_version = version;
}

void rpc_debmod_t::process_banks_info(uchar *body) {
  std::map<qstring, uint16> banks;
  auto items = *((uint16 *)body);
  body += 2;
  while (items--) {
    body++;
    auto bank_id = *((uint16 *)body);
    auto name = qstring((char *)body + 3, body[2]);
    banks[name] = bank_id;
    body += 3 + body[2];
  }
  bank_map = banks;
}

static int convert_vice_register_to_register_index(const qstring &name) {
  static std::map<qstring, uint32> vice_to_reg_index = {
    { "A", 0 },
    { "X", 1 },
    { "Y", 2 },
    { "PC", 3 },
    { "SP", 4 },
    { "FL", 5 },
    { "LIN", 6 },
    { "CYC", 7 },
    { "00", 8 },
    { "01", 9 },
  };
  auto it = vice_to_reg_index.find(name);
  if (it == vice_to_reg_index.end())
    return -1;
  else
    return it->second;
}

void rpc_debmod_t::process_registers_info(uchar *body) {
  std::map<uchar, int> regs;
  auto items = *((uint16 *)body);
  body += 2;
  while (items--) {
    auto reg_id = body[1];
    auto name = qstring((char *)body + 4, body[3]);
    auto register_index = convert_vice_register_to_register_index(name);
    if (register_index == -1) {
      msg("Unknown VICE register %s. Will ignore.\n", name.c_str());
      continue;
    }
    msg("Mapping VICE register %d %s to register #%d\n",
        reg_id, name.c_str(), register_index);
    regs[reg_id] = register_index;
    body += 4 + body[3];
  }
  register_map = regs;
}

void rpc_debmod_t::process_stopped(uchar *body) {
  if (!is_process_running)
    return;

  auto event = debug_event_t();
  event.eid = PROCESS_SUSPEND;
  event.pid = 1;
  event.tid = 1;
  event.ea = *((uint16 *)body);
  event.handled = true;
  enqueue_event(event);
}

void rpc_debmod_t::process_started(uchar *body) {
}

void rpc_debmod_t::process_response(mon_response_t *response) {
  auto code = response->response_type;
  if (code == MON_RESPONSE_VICE_INFO)
    process_vice_info(response->body);
  else if (code == MON_RESPONSE_BANKS_AVAILABLE)
    process_banks_info(response->body);
  else if (code == MON_RESPONSE_REGISTERS_AVAILABLE)
    process_registers_info(response->body);
  else if (code == MON_RESPONSE_STOPPED)
    process_stopped(response->body);
  else if (code == MON_RESPONSE_AUTOSTART)
    process_started(response->body);
  else
    msg("No processor for response %s\n", get_mon_response_name(code));
}

mon_response_t *rpc_debmod_t::wait_for_response(uint32 req_id) {
  while (irs_ready(irs, 200)) {
    auto response = recv_response();
    process_response(response);
    if (response->request_id == req_id)
      return response;
    qfree(response);
  }
  return nullptr;
}

void rpc_debmod_t::flush_responses() {
  // TODO: Remove this unused method, should use wait_for_response instead
  while (irs_ready(irs, 200)) {
    auto response = recv_response();
    process_response(response);
    qfree(response);
  }
}

void rpc_debmod_t::query_info() {
  cmd_query_banks();
  cmd_query_registers(kMemSpaceMainMemory);
  auto request_id = cmd_query_vice_info();
  wait_for_response(request_id);
}

void rpc_debmod_t::enqueue_event(const debug_event_t &event) {
  msg("*** Enqueueing event: {eid=%s ea=0x%08llX, handled=%s}\n",
      get_event_name(event.eid), event.ea,
      event.handled ? "true" : "false");
  
  event_queue.push_back(event);
}

bool rpc_debmod_t::has_pending_events() const {
  return !event_queue.empty();
}

debug_event_t rpc_debmod_t::dequeue_event() {
  auto rv = event_queue.front();
  event_queue.pop_front();
  return rv;
}

//--------------------------------------------------------------------------
bool idaapi rpc_debmod_t::open_remote(
        const char *hostname,
        int port_number,
        const char *password)
{
  network_error_code = 0;
  irs = init_client_irs(hostname, port_number);
  if ( irs == NULL )
  {
FAILURE:
    term_irs();
    return false;
  }

  query_info();
  msg("Successfully connected to Vice version %s\n", vice_version.c_str());
  return true;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_add_bpt(bpttype_t, ea_t, int)
{
  INTERR(30114);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_del_bpt(bpttype_t, ea_t, const uchar *, int)
{
  INTERR(30115);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds)
{
  ea_t ea = 0;
  bytevec_t req = prepare_rpc_packet(RPC_UPDATE_LOWCNDS);
  append_dd(req, nlowcnds);
  const lowcnd_t *lc = lowcnds;
  for ( int i=0; i < nlowcnds; i++, lc++ )
  {
    append_ea64(req, lc->ea-ea); ea = lc->ea;
    append_str(req, lc->cndbody);
    if ( !lc->cndbody.empty() )
    {
      append_dd(req, lc->type);
      if ( lc->type != BPT_SOFT )
        append_dd(req, lc->size);
      append_db(req, lc->orgbytes.size());
      append_memory(req, lc->orgbytes.begin(), lc->orgbytes.size());
      append_ea64(req, lc->cmd.ea);
      if ( lc->cmd.ea != BADADDR )
        append_memory(req, &lc->cmd, sizeof(lc->cmd));
    }
  }
  return process_long(req);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_eval_lowcnd(thid_t tid, ea_t ea)
{
  bytevec_t req = prepare_rpc_packet(RPC_EVAL_LOWCND);
  append_dd(req, tid);
  append_ea64(req, ea);
  return process_long(req);
}

//--------------------------------------------------------------------------
static uint8 convert_flags(bpttype_t type) {
  auto rv = kCpuOperationNone;
  if (type & BPT_READ)
    rv |= kCpuOperationLoad;
  if (type & BPT_WRITE)
    rv |= kCpuOperationStore;
  if (type & (BPT_SOFT | BPT_EXEC))
    rv |= kCpuOperationExec;
  return rv;
}

bool rpc_debmod_t::set_breakpoint(update_bpt_info_t &bp) {
  auto flags = convert_flags(bp.type);
  auto request_id = cmd_set_checkpoint(bp.ea, bp.ea + bp.size, true, true, flags, false, kMemSpaceMainMemory);
  auto response = wait_for_response(request_id);
  if (!response) {
    msg("Unable to set breakpoint at address $%04llX\n", bp.ea);
    bp.code = BPT_INTERNAL_ERR;
    return false;
  }

  auto checkpoint_number = *((uint32 *)response->body);
  qfree(response);
  breakpoints[checkpoint_number] = bp;
  msg("Breakpoint #%d set at address ($%04llX)\n", checkpoint_number, bp.ea);
  bp.code = BPT_OK;
  if (bp.type & BPT_SOFT)
    bp.orgbytes = bytevec_t(&bp.code, 1);
  return true;
}

bool rpc_debmod_t::delete_breakpoint(const update_bpt_info_t &bp) {
  auto it = std::find_if(breakpoints.begin(), breakpoints.end(), [&](auto &arg) {
    return arg.second.ea == bp.ea;
  });
  if (it == breakpoints.end()) {
    msg("Unable to find breakpoing for address $%04llX\n", bp.ea);
    return false;
  }
  msg("Deleting breakpoint #%d ($%04llX)\n", it->first, bp.ea);
  cmd_delete_checkpoint(it->first);
  breakpoints.erase(it);
  return true;
}

int idaapi rpc_debmod_t::dbg_update_bpts(update_bpt_info_t *ubpts, int nadd, int ndel)
{
  int rv = 0;
  for (auto bpt = ubpts; nadd; --nadd, ++bpt) {
    if (set_breakpoint(*bpt))
      rv++;
  }

  for (auto bpt = ubpts + nadd; ndel; --ndel, ++bpt) {
    if (delete_breakpoint(*bpt))
      rv++;
  }

  return rv;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_thread_get_sreg_base(ea_t *ea, thid_t tid, int sreg_value)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_SREG_BASE);
  append_dd(req, tid);
  append_dd(req, sreg_value);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end) != 0;

  if ( result )
    *ea = extract_ea64(&answer, end);

  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_set_exception_info(const exception_info_t *table, int qty)
{
  // TODO: If appropriate, tell VICE what to do on particular exceptions (JAM? etc)
  // For now, do nothing
//  bytevec_t req = prepare_rpc_packet(RPC_SET_EXCEPTION_INFO);
//  append_dd(req, qty);
//  append_exception_info(req, table, qty);
//
//  qfree(process_request(req));
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_open_file(const char *file, uint64 *fsize, bool readonly)
{
  bytevec_t req = prepare_rpc_packet(RPC_OPEN_FILE);
  append_str(req, file);
  append_dd(req, readonly);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int fn = extract_long(&answer, end);
  if ( fn != -1 )
  {
    if ( fsize != NULL && readonly )
      *fsize = extract_uint64(&answer, end);
  }
  else
  {
    qerrcode(extract_long(&answer, end));
  }
  qfree(rp);
  return fn;
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_close_file(int fn)
{
  bytevec_t req = prepare_rpc_packet(RPC_CLOSE_FILE);
  append_dd(req, fn);

  qfree(process_request(req));
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_read_file(int fn, qoff64_t off, void *buf, size_t size)
{
  bytevec_t req = prepare_rpc_packet(RPC_READ_FILE);
  append_dd(req, fn);
  append_dq(req, off);
  append_dd(req, (uint32)size);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int32 rsize = extract_long(&answer, end);
  if ( size != rsize )
    qerrcode(extract_long(&answer, end));

  if ( rsize > 0 )
  {
    QASSERT(1204, rsize <= size);
    extract_memory(&answer, end, buf, rsize);
  }
  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
ssize_t idaapi rpc_debmod_t::dbg_write_file(int fn, qoff64_t off, const void *buf, size_t size)
{
  bytevec_t req = prepare_rpc_packet(RPC_WRITE_FILE);
  append_dd(req, fn);
  append_dq(req, off);
  append_dd(req, (uint32)size);
  append_memory(req, buf, size);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int32 rsize = extract_long(&answer, end);
  if ( size != rsize )
    qerrcode(extract_long(&answer, end));

  qfree(rp);
  return rsize;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  return BPT_OK;
}

//--------------------------------------------------------------------------
int rpc_debmod_t::getint2(uchar code, int x)
{
  bytevec_t req = prepare_rpc_packet(code);
  append_dd(req, x);

  return process_long(req);
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_init(void)
{
  // TODO: Maybe do initialization done elsewhere here?
  return 1; // process_long(req);
}

//--------------------------------------------------------------------------
void idaapi rpc_debmod_t::dbg_term(void)
{
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_get_processes(procinfo_vec_t *procs)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_PROCESSES);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;
  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  procs->qclear();
  bool result = extract_long(&answer, end) != 0;
  if ( result )
    extract_process_info_vec(&answer, end, procs);

  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_detach_process(void)
{
  return getint(RPC_DETACH_PROCESS);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32)
{
  auto event = debug_event_t();
  event.eid = PROCESS_START;
  event.pid = 1;
  event.tid = 1;
  event.ea = BADADDR;
  event.handled = true;
  qstrncpy(event.modinfo.name, path, MAXSTR);
  event.modinfo.base = BADADDR;
  event.modinfo.size = 0;
  event.modinfo.rebase_to = BADADDR;
  enqueue_event(event);

  // Allow future MON_RESPONSE_STOPPED caused by ping to cause PROCESS_SUSPEND events
  is_process_running = true;

  cmd_load(path);
  auto request_id = cmd_ping();
  wait_for_response(request_id);
  return 1;
}

//--------------------------------------------------------------------------
gdecode_t idaapi rpc_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  if (!has_pending_events() && irs_ready(irs, timeout_ms)) {
    verbev(("get_debug_event => no pending events but remote has packets for us\n"));
    auto response = recv_response();
    process_response(response);
    qfree(response);
  }

  if (has_pending_events()) {
    verbev(("get_debug_event => has pending events, returning one\n"));
    *event = dequeue_event();
    return !has_pending_events() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
  }

  return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_attach_process(pid_t _pid, int event_id, int flags)
{
  bytevec_t req = prepare_rpc_packet(RPC_ATTACH_PROCESS);
  append_dd(req, _pid);
  append_dd(req, event_id);
  append_dd(req, flags);
  return process_start_or_attach(req);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_prepare_to_pause_process(void)
{
  auto req_id = cmd_ping();
  auto response = wait_for_response(req_id);
  if (!response)
    return -1;
  if (response->error_code != MON_ERR_OK)
    return 0;
  return 1;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_exit_process(void)
{
  auto req_id = cmd_reset();
  wait_for_response(req_id);

  auto event = debug_event_t();
  event.eid = PROCESS_EXIT;
  event.pid = 1;
  event.tid = 1;
  event.handled = true;
  event.exit_code = 0;
  enqueue_event(event);

  return 1;
}

//--------------------------------------------------------------------------
/// Continue after handling the event.
/// This function is called from debthread.
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi rpc_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  // Do not continue after process start
  // This is because a PROCESS_SUSPEND event should already be awaiting
  if (event->eid == PROCESS_SUSPEND && has_pending_events())
    return 1;

  auto saved_resume_mode = resume_mode;
  resume_mode = RESMOD_NONE;

  auto request_id = resume_execution(saved_resume_mode);
  if (request_id == 0)
    return 0;
  auto response = wait_for_response(request_id);
  if (!response)
    return -1;
  if (response->error_code != MON_ERR_OK)
    return 0;
  return 1;
}

//--------------------------------------------------------------------------
/// This function will be called by the kernel each time
/// it has stopped the debugger process and refreshed the database.
/// The debugger module may add information to the database if it wants.
///
/// The reason for introducing this function is that when an event line
/// LOAD_DLL happens, the database does not reflect the memory state yet
/// and therefore we can't add information about the dll into the database
/// in the get_debug_event() function.
/// Only when the kernel has adjusted the database we can do it.
/// Example: for imported PE DLLs we will add the exported function
/// names to the database.
///
/// This function pointer may be absent, i.e. NULL.
/// This function is called from the main thread.
void idaapi rpc_debmod_t::dbg_stopped_at_debug_event(void)
{
  // TODO: Anything here? Prob not.
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_thread_suspend(thid_t tid)
{
  return getint2(RPC_TH_SUSPEND, tid);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_thread_continue(thid_t tid)
{
  return getint2(RPC_TH_CONTINUE, tid);
}

//--------------------------------------------------------------------------
uint32 rpc_debmod_t::resume_execution(resume_mode_t resmod) {
  switch (resmod) {
    case RESMOD_NONE:
      return cmd_exit();
    case RESMOD_INTO:
      return cmd_advance_instructions(false, 1);
    case RESMOD_OVER:
      return cmd_advance_instructions(true, 1);
    case RESMOD_OUT:
      return cmd_execute_until_return();
    default:
      msg("Unsupport resume mode %d\n", resmod);
      return 0;
  }
}

int idaapi rpc_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  switch (resmod) {
    case RESMOD_NONE:
    case RESMOD_INTO:
    case RESMOD_OVER:
    case RESMOD_OUT:
      resume_mode = resmod;
      return 1;
    default:
      msg("Unsupport resume mode %d\n", resmod);
      return 0;
  }
}

//--------------------------------------------------------------------------
/// Read thread registers.
/// This function is called from debthread.
/// \param tid      thread id
/// \param clsmask  bitmask of register classes to read
/// \param values   pointer to vector of regvals for all registers.
///                 regval is assumed to have debugger_t::registers_size elements
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi rpc_debmod_t::dbg_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  auto req_id = cmd_get_registers();
  auto response = wait_for_response(req_id);
  if (response == nullptr)
    return -1;
  if (response->error_code != MON_ERR_OK)
    return 0;

  auto ptr = response->body;
  auto count = *((uint16 *)ptr);
  ptr += 2;
  for (auto n = 0; n != count; ++n) {
    auto reg_id = ptr[1];
    auto reg_value = *((uint16 *)(ptr + 2));
    auto it = register_map.find(reg_id);
    if (it == register_map.end())
      continue;
    auto register_index = it->second;
    // TODO: Use constants here, SP special case
    if (register_index == 4)
      reg_value |= 0x100;
    values[register_index].rvtype = RVT_INT;
    values[register_index].ival = reg_value;
    ptr += 4;
  }
  qfree(response);
  return 1;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  bytevec_t req = prepare_rpc_packet(RPC_WRITE_REG);
  append_dd(req, tid);
  append_dd(req, reg_idx);
  append_regvals(req, value, 1, NULL);

  return process_long(req);
}

//--------------------------------------------------------------------------
/// Get information on the memory ranges.
/// The debugger module fills 'ranges'. The returned vector MUST be sorted.
/// This function is called from debthread.
/// \retval  -3  use idb segmentation
/// \retval  -2  no changes
/// \retval  -1  the process does not exist anymore
/// \retval   0  failed
/// \retval   1  new memory layout is returned
int idaapi rpc_debmod_t::dbg_get_memory_info(meminfo_vec_t &areas)
{
  memory_info_t info;
  info.start_ea = 0x0000;
  info.end_ea = 0x10000;
  info.sbase = 0x0000;
  info.bitness = 0;
  info.perm = SEGPERM_EXEC | SEGPERM_READ | SEGPERM_WRITE;
  areas.push_back(info);
  return 1;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_get_scattered_image(scattered_image_t &si, ea_t base)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_SCATTERED_IMAGE);
  append_ea64(req, base);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return false;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end) - 2;
  if ( result > 0 )
  {
    int n = extract_long(&answer, end);
    si.resize(n);
    for ( int i=0; i < n; i++ )
      extract_scattered_segm(&answer, end, &si[i]);
  }
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
bool idaapi rpc_debmod_t::dbg_get_image_uuid(bytevec_t *uuid, ea_t base)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_IMAGE_UUID);
  append_ea64(req, base);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return false;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end) != 0;
  if ( result )
  {
    int n = extract_long(&answer, end);
    uuid->append(answer, n);
  }
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ea_t idaapi rpc_debmod_t::dbg_get_segm_start(ea_t base, const qstring &segname)
{
  bytevec_t req = prepare_rpc_packet(RPC_GET_SEGM_START);
  append_ea64(req, base);
  append_str(req, segname.c_str());

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return false;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  ea_t result = extract_ea64(&answer, end);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
/// Read process memory.
/// Returns number of read bytes.
/// This function is called from debthread.
/// \retval 0  read error
/// \retval -1 process does not exist anymore
ssize_t idaapi rpc_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size)
{
  auto request_id = cmd_memory_get(ea, ea + size - 1, "cpu");
  auto response = wait_for_response(request_id);
  if (!response)
    return -1;
  if (response->error_code != MON_ERR_OK)
    return 0;
  auto length = *((uint16 *)response->body);
  auto read = qmin(size, length);
  memcpy(buffer, response->body + 2, read);
  return read;
}

//--------------------------------------------------------------------------
/// Write process memory.
/// This function is called from debthread.
/// \return number of written bytes, -1 if fatal error
ssize_t idaapi rpc_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size)
{
  bytevec_t req = prepare_rpc_packet(RPC_WRITE_MEMORY);
  append_ea64(req, ea);
  append_dd(req, (uint32)size);
  append_memory(req, buffer, size);

  return process_long(req);
}

//--------------------------------------------------------------------------
bool idaapi rpc_debmod_t::dbg_update_call_stack(thid_t tid, call_stack_t *trace)
{
  bytevec_t req = prepare_rpc_packet(RPC_UPDATE_CALL_STACK);
  append_dd(req, tid);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return false;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  bool result = extract_long(&answer, end) != 0;
  if ( result )
    extract_call_stack(&answer, end, trace);
  qfree(rp);
  return result;
}

//--------------------------------------------------------------------------
ea_t idaapi rpc_debmod_t::dbg_appcall(
        ea_t func_ea,
        thid_t tid,
        int stkarg_nbytes,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int flags)
{
  bytevec_t req = prepare_rpc_packet(RPC_APPCALL);
  append_ea64(req, func_ea);
  append_dd(req, tid);
  append_dd(req, stkarg_nbytes);
  append_dd(req, flags);
  regobjs_t *rr = (flags & APPCALL_MANUAL) == 0 ? retregs : NULL;
  append_appcall(req, *regargs, *stkargs, rr);

  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return BADADDR;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  ea_t sp = extract_ea64(&answer, end);
  if ( sp == BADADDR )
  {
    if ( (flags & APPCALL_DEBEV) != 0 )
      extract_debug_event(&answer, end, event);
    if ( errbuf != NULL )
      *errbuf = extract_str(&answer, end);
  }
  else if ( (flags & APPCALL_MANUAL) == 0 )
  {
    if ( retregs != NULL )
      extract_regobjs(&answer, end, retregs, true);
  }
  qfree(rp);
  return sp;
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_cleanup_appcall(thid_t tid)
{
  bytevec_t req = prepare_rpc_packet(RPC_CLEANUP_APPCALL);
  append_dd(req, tid);
  return process_long(req);
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::dbg_rexec(const char *cmdline)
{
  bytevec_t req = prepare_rpc_packet(RPC_REXEC);
  append_str(req, cmdline);
  return process_long(req);
}

//--------------------------------------------------------------------------
bool rpc_debmod_t::close_remote()
{
  term_client_irs(irs);
  irs = NULL;
  network_error_code = 0;
  return true;
}

//--------------------------------------------------------------------------
void rpc_debmod_t::neterr(const char *module)
{
  int code = irs_error(irs);
  error("%s: %s", module, winerr(code));
}

//--------------------------------------------------------------------------
int idaapi rpc_debmod_t::get_system_specific_errno(void) const
{
  return irs_error(irs);
}

//-------------------------------------------------------------------------
int rpc_debmod_t::process_start_or_attach(bytevec_t &req)
{
  rpc_packet_t *rp = process_request(req);
  if ( rp == NULL )
    return -1;

  const uchar *answer = (uchar *)(rp+1);
  const uchar *end = answer + rp->length;

  int result = extract_long(&answer, end);
  if ( result > 0 )
    extract_debapp_attrs(&answer, end, &debapp_attrs);
  qfree(rp);
  return result;
}
