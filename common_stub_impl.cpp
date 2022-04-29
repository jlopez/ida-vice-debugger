//
// This file is included from other files, do not directly compile it.
// It contains the implementation of debugger plugin callback functions
//

#include <err.h>
#include <name.hpp>
#include <expr.hpp>
#include <segment.hpp>
#include <typeinf.hpp>

//---------------------------------------------------------------------------
//lint -esym(714, rebase_or_warn) not referenced
int rebase_or_warn(ea_t base, ea_t new_base)
{
  int code = rebase_program(new_base - base, MSF_FIXONCE);
  if ( code != MOVE_SEGM_OK )
  {
    msg("Failed to rebase program, error code %d\n", code);
    warning("IDA failed to rebase the program.\n"
      "Most likely it happened because of the debugger\n"
      "segments created to reflect the real memory state.\n\n"
      "Please stop the debugger and rebase the program manually.\n"
      "For that, please select the whole program and\n"
      "use Edit, Segments, Rebase program with delta 0x%08llX",
      new_base - base);
  }
  return code;
}

//---------------------------------------------------------------------------
void idaapi s_stopped_at_debug_event(void)
{
  // Let the debugger module populate the names
  g_dbgmod.dbg_stopped_at_debug_event();
}

//--------------------------------------------------------------------------
// This code is compiled for local debuggers (like win32_user.plw)
#ifndef RPC_CLIENT

ssize_t dvmsg(int code, rpc_engine_t *, const char *format, va_list va)
{
  if ( code == 0 )
    return vmsg(format, va);
  if ( code > 0 )
    vwarning(format, va);
  else
    verror(format, va);
  return 0;
}

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

#endif // end of 'local debugger' code

bool lock_begin(void)
{
  return true;
}

bool lock_end(void)
{
  return true;
}

//--------------------------------------------------------------------------
void report_idc_error(
        rpc_engine_t *,
        ea_t ea,
        error_t code,
        ssize_t errval,
        const char *errprm)
{
  // Copy errval/errprm to the locations expected by qstrerror()
  if ( errprm != NULL && errprm != get_error_string(0) )
    QPRM(1, errprm);
  else if ( code == eOS )
    errno = errval;
  else
    set_error_data(0, errval);

  warning("AUTOHIDE NONE\n%llX: %s", ea, qstrerror(code));
}

//--------------------------------------------------------------------------
int for_all_debuggers(debmod_visitor_t &v)
{
  return v.visit(&g_dbgmod);
}

gdecode_t idaapi s_get_debug_event(debug_event_t *event, int timeout_ms)
{
  auto rv = g_dbgmod.dbg_get_debug_event(event, timeout_ms);
  if (rv >= GDE_ONE_EVENT) {
    msg(API_RECV "%s(timeout_ms=%d)\n", __func__, timeout_ms);
    msg(API_RESP "%s -> event={eid=%s ea=0x%08llX, handled=%s}%s\n",
        __func__, get_event_name(event->eid), event->ea,
        event->handled ? "true" : "false",
        rv == GDE_MANY_EVENTS ? "..." : "");
  }
  //else
  //  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_write_register(thid_t tid, int reg_idx, const regval_t *value)
{
  return g_dbgmod.dbg_write_register(tid, reg_idx, value);
}

int idaapi s_read_registers(thid_t tid, int clsmask, regval_t *values)
{
  return g_dbgmod.dbg_read_registers(tid, clsmask, values);
}

int idaapi s_is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  return g_dbgmod.dbg_is_ok_bpt(type, ea, len);
}

int idaapi s_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  return g_dbgmod.dbg_update_bpts(bpts, nadd, ndel);
}

int idaapi s_update_lowcnds(const lowcnd_t *lowcnds, int nlowcnds)
{
  msg(API_RECV "%s(lowcnds={ea=0x%08llX, cndbody=%s, type=0x%04X}, nlowcnds=%d)\n", __func__, lowcnds->ea, lowcnds->cndbody.c_str(), lowcnds->type, nlowcnds);
  auto rv = g_dbgmod.dbg_update_lowcnds(lowcnds, nlowcnds);
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_eval_lowcnd(thid_t tid, ea_t ea)
{
  msg(API_RECV "%s(tid=0x%04X, ea=0x%08llX)\n", __func__, tid, ea);
  auto rv = g_dbgmod.dbg_eval_lowcnd(tid, ea);
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_get_processes(procinfo_vec_t *proclist)
{
  msg(API_RECV "%s()\n", __func__);
  auto rv = g_dbgmod.dbg_get_processes(proclist);
  for (auto n = 0; n != proclist->size(); ++n) {
    msg(API_HEAD "%d. %5d %s\n", n + 1, (*proclist)[n].pid, (*proclist)[n].name.c_str());
  }
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

void idaapi s_set_debugging(bool _debug_debugger)
{
  g_dbgmod.dbg_set_debugging(_debug_debugger);
}

int idaapi s_init(void)
{
  g_dbgmod.debugger_flags = debugger.flags;
  return g_dbgmod.dbg_init();
}

int idaapi s_attach_process(pid_t process_id, int event_id, int flags)
{
  msg(API_RECV "%s(process_id=%d, event_id=0x%04X, flags=0x%04X)\n", __func__, process_id, event_id, flags);
  int rc = g_dbgmod.dbg_attach_process(process_id, event_id, flags);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

int idaapi s_detach_process(void)
{
  msg(API_RECV "%s()\n", __func__);
  auto rv = g_dbgmod.dbg_detach_process();
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_prepare_to_pause_process(void)
{
  msg(API_RECV "%s()\n", __func__);
  auto rv = g_dbgmod.dbg_prepare_to_pause_process();
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_exit_process(void)
{
  msg(API_RECV "%s()\n", __func__);
  auto rv = g_dbgmod.dbg_exit_process();
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_continue_after_event(const debug_event_t *event)
{
  msg(API_RECV "%s(event={eid=%s ea=0x%08llX, handled=%s})\n", __func__,
      get_event_name(event->eid), event->ea, event->handled ? "true" : "false");
  auto rv = g_dbgmod.dbg_continue_after_event(event);
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

void idaapi s_set_exception_info(const exception_info_t *info, int qty)
{
  msg(API_RECV "%s(qty=%d)\n", __func__, qty);
  for (auto i = 0; i != qty; ++i) {
    msg(API_HEAD "%d. {code=%d, flags=0x%04X, name=%s, desc=%s}\n", i + 1,
        info[i].code, info[i].flags, info[i].name.c_str(), info[i].desc.c_str());
  }
  g_dbgmod.dbg_set_exception_info(info, qty);
}

int idaapi s_thread_suspend(thid_t thread_id)
{
  msg(API_RECV "%s(thread_id=%d)\n", __func__, thread_id);
  auto rv = g_dbgmod.dbg_thread_suspend(thread_id);
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_thread_continue(thid_t thread_id)
{
  msg(API_RECV "%s(thread_id=%d)\n", __func__, thread_id);
  auto rv = g_dbgmod.dbg_thread_continue(thread_id);
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

int idaapi s_set_resume_mode(thid_t thread_id, resume_mode_t resmod)
{
  msg(API_RECV "%s(thread_id=%d, resmod=%d)\n", __func__, thread_id, resmod);
  auto rv = g_dbgmod.dbg_set_resume_mode(thread_id, resmod);
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

ssize_t idaapi s_read_memory(ea_t ea, void *buffer, size_t size)
{
  msg(API_RECV "%s(ea=0x%08llX, size=0x%04zX)\n", __func__, ea, size);
  auto rv = g_dbgmod.dbg_read_memory(ea, buffer, size);
  msg(API_RESP "%s -> %ld\n", __func__, rv);
  return rv;
}

ssize_t idaapi s_write_memory(ea_t ea, const void *buffer, size_t size)
{
  msg(API_RECV "%s(ea=0x%08llX, size=0x%04zX)\n", __func__, ea, size);
  auto rv = g_dbgmod.dbg_write_memory(ea, buffer, size);
  msg(API_RESP "%s -> %ld\n", __func__, rv);
  return rv;
}

/// Get information about the base of a segment register.
/// Currently used by the IBM PC module to resolve references like fs:0.
/// This function is called from debthread.
/// \param answer      pointer to the answer. can't be NULL.
/// \param tid         thread id
/// \param sreg_value  value of the segment register (returned by get_reg_val())
/// \retval  1  ok
/// \retval  0  failed
/// \retval -1  network error
int idaapi s_thread_get_sreg_base(ea_t *ea, thid_t thread_id, int sreg_value)
{
  msg(API_RECV "%s(thread_id=%d, sreg_value=0x%04X)\n", __func__, thread_id, sreg_value);
  auto rv = g_dbgmod.dbg_thread_get_sreg_base(ea, thread_id, sreg_value);
  msg(API_RESP "%s -> %d ea=0x%08llX\n", __func__, rv, *ea);
  return rv;
}

/// Map process address.
/// This function may be absent.
/// This function is called from debthread.
/// \param ea       offset to map
/// \param regs     current register values. if regs == NULL, then perform
///                 global mapping, which is independent on used registers
///                 usually such a mapping is a trivial identity mapping
/// \param regnum   required mapping. maybe specified as a segment register number
///                 or a regular register number if the required mapping can be deduced
///                 from it. for example, esp implies that ss should be used.
/// \return mapped address or #BADADDR
ea_t idaapi s_map_address(ea_t ea, const regval_t *regs, int regnum)
{
  msg(API_RECV "%s(ea=0x%08llX, regs=%p, regnum=%d)\n", __func__, ea, regs, regnum);
  auto rv = g_dbgmod.map_address(ea, regs, regnum);
  msg(API_RESP "%s -> %llu\n", __func__, rv);
  return rv;
}

/// Set debugger options (parameters that are specific to the debugger module).
/// See the definition of ::set_options_t for arguments.
/// See the convenience function in dbg.hpp if you need to call it.
/// The kernel will call this function after reading the debugger specific
/// config file (arguments are: keyword="", type=#IDPOPT_STR, value="")
/// This function is optional.
/// This function is called from the main thread
//*** s_set_dbg_options(keyword=, pri=1, value_type=IDPOPT_STR, value=)
//*** s_set_dbg_options(keyword=TraceWindowOpt, pri=1, value_type=IDPOPT_NUM, value=0)
//*** s_set_dbg_options(keyword=TracingStepOpt, pri=1, value_type=IDPOPT_NUM, value=3)
//*** s_set_dbg_options(keyword=TracingInsnOpt, pri=1, value_type=IDPOPT_NUM, value=0)
//*** s_set_dbg_options(keyword=TracingBblkOpt, pri=1, value_type=IDPOPT_NUM, value=1)
//*** s_set_dbg_options(keyword=TracingFuncOpt, pri=1, value_type=IDPOPT_NUM, value=1)
//*** s_set_dbg_options(keyword=TracingHighlight, pri=1, value_type=IDPOPT_NUM, value=1)
//*** s_set_dbg_options(keyword=TracingHighlightColor, pri=1, value_type=IDPOPT_NUM, value=12648447)
//*** s_set_dbg_options(keyword=TracingHighlightDiff, pri=1, value_type=IDPOPT_NUM, value=11910399)
//*** s_set_dbg_options(keyword=TracingBufferSize, pri=1, value_type=IDPOPT_NUM, value=1000000)
//*** s_set_dbg_options(keyword=TracingMemorySize, pri=1, value_type=IDPOPT_NUM, value=0)
//*** s_set_dbg_options(keyword=TracingBufferSize, pri=1, value_type=IDPOPT_NUM, value=1000000)
const char * idaapi s_set_dbg_options(const char *keyword, int pri, int value_type, const void *value) {
  if (value_type == IDPOPT_STR)
    msg(API_RECV "%s(keyword=%s, pri=%d, value_type=IDPOPT_STR, value=%s)\n", __func__, keyword, pri, (const char *)value);
  else if (value_type == IDPOPT_NUM)
    msg(API_RECV "%s(keyword=%s, pri=%d, value_type=IDPOPT_NUM, value=%llu)\n", __func__, keyword, pri, *((uval_t*)value));
  else if (value_type == IDPOPT_BIT)
    msg(API_RECV "%s(keyword=%s, pri=%d, value_type=IDPOPT_BIT, value=%d)\n", __func__, keyword, pri, *((int*)value));
  else if (value_type == IDPOPT_I64)
    msg(API_RECV "%s(keyword=%s, pri=%d, value_type=IDPOPT_I64, value=%lld)\n", __func__, keyword, pri, *((int64*)value));
  else if (value_type == IDPOPT_CST)
    msg(API_RECV "%s(keyword=%s, pri=%d, value_type=IDPOPT_CST, value=%p)\n", __func__, keyword, pri, value);
  else
    msg(API_RECV "%s(keyword=%s, pri=%d, value_type=%d, value=%p)\n", __func__, keyword, pri, value_type, value);
  return IDPOPT_OK;
}

/// Get pointer to debugger specific functions.
/// This function returns a pointer to a structure that holds pointers to
/// debugger module specific functions. For information on the structure
/// layout, please check the corresponding debugger module. Most debugger
/// modules return NULL because they do not have any extensions. Available
/// extensions may be called from plugins.
/// This function is called from the main thread.
const void * idaapi s_get_debmod_extensions(void) {
  msg(API_RECV "%s()\n", __func__);
  return nullptr;
}


//---------------------------------------------------------------------------
int idaapi s_get_memory_info(meminfo_vec_t &ranges)
{
  msg(API_RECV "%s()\n", __func__);
  auto rv = g_dbgmod.dbg_get_memory_info(ranges);
  for (auto n = 0; n != ranges.size(); ++n) {
    msg(API_HEAD "%d. range={name=%s, sclass=%s, sbase=0x%08llX, bitness=%d, perm=%d}\n",
        n + 1, ranges[n].name.c_str(), ranges[n].sclass.c_str(), ranges[n].sbase, ranges[n].bitness, ranges[n].perm);
  }
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

//---------------------------------------------------------------------------
/// Start an executable to debug.
/// This function is called from debthread.
/// \param path              path to executable
/// \param args              arguments to pass to executable
/// \param startdir          current directory of new process
/// \param flags    \ref DBG_PROC_
/// \param input_path        path to database input file.
///                          (not always the same as 'path' - e.g. if you're analyzing
///                          a dll and want to launch an executable that loads it)
/// \param input_file_crc32  CRC value for 'input_path'
/// \retval  1                    ok
/// \retval  0                    failed
/// \retval -2                    file not found (ask for process options)
/// \retval  1 | #CRC32_MISMATCH  ok, but the input file crc does not match
/// \retval -1                    network error
int idaapi s_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32)
{
  msg(API_RECV "%s(path=%s, args=%s, startdir=%s, flags=0x%04X, input_path=%s, input_file_crc32=0x%08X)\n", __func__,
      path, args, startdir, flags, input_path, input_file_crc32);
  int rc = g_dbgmod.dbg_start_process(path,
                                      args,
                                      startdir,
                                      flags,
                                      input_path,
                                      input_file_crc32);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
int idaapi s_open_file(const char *file, uint64 *fsize, bool readonly)
{
  msg(API_RECV "%s(file=%s, readonly=%s)\n", __func__, file, readonly ? "true" : "false");
  auto rc = g_dbgmod.dbg_open_file(file, fsize, readonly);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
void idaapi s_close_file(int fn)
{
  msg(API_RECV "%s(fn=%d)\n", __func__, fn);
  g_dbgmod.dbg_close_file(fn);
}

//--------------------------------------------------------------------------
ssize_t idaapi s_read_file(int fn, qoff64_t off, void *buf, size_t size)
{
  msg(API_RECV "%s(fn=%d, off=0x%08llX, size=0x%04zX)\n", __func__, fn, off, size);
  auto rc = g_dbgmod.dbg_read_file(fn, off, buf, size);
  msg(API_RESP "%s -> %ld\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
ssize_t idaapi s_write_file(int fn, qoff64_t off, const void *buf, size_t size)
{
  msg(API_RECV "%s(fn=%d, off=0x%08llX, size=0x%04zX)\n", __func__, fn, off, size);
  auto rc = g_dbgmod.dbg_write_file(fn, off, buf, size);
  msg(API_RESP "%s -> %ld\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
/// Calculate the call stack trace.
/// This function is called when the process is suspended and should fill
/// the 'trace' object with the information about the current call stack.
/// If this function is missing or returns false, IDA will use the standard
/// mechanism (based on the frame pointer chain) to calculate the stack trace
/// This function is called from the main thread.
/// \return success
bool idaapi s_update_call_stack(thid_t tid, call_stack_t *trace)
{
  msg(API_RECV "%s(tid=%d, trace={size=%zu, dirty=%s})\n", __func__, tid, trace->size(), trace->dirty ? "true": "false");
  auto rc = g_dbgmod.dbg_update_call_stack(tid, trace);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
ea_t idaapi s_appcall(
        ea_t func_ea,
        thid_t tid,
        const struct func_type_data_t *fti,
        int /*nargs*/,
        const struct regobjs_t *regargs,
        struct relobj_t *stkargs,
        struct regobjs_t *retregs,
        qstring *errbuf,
        debug_event_t *event,
        int flags)
{
  msg(API_RECV "%s(func_ea=0x%08llX, tid=%d)\n", __func__, func_ea, tid);
  auto rc = g_dbgmod.dbg_appcall(func_ea,
                              tid,
                              fti->stkargs,
                              regargs,
                              stkargs,
                              retregs,
                              errbuf,
                              event,
                              flags);
  msg(API_RESP "%s -> %llu\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
int idaapi s_cleanup_appcall(thid_t tid)
{
  msg(API_RECV "%s(tid=%d)\n", __func__, tid);
  auto rc = g_dbgmod.dbg_cleanup_appcall(tid);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
int idaapi s_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  msg(API_RECV "%s(fn=%d, size=0x%04zX)\n", __func__, fn, size);
  auto rc = g_dbgmod.handle_ioctl(fn, buf, size, poutbuf, poutsize);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
bool idaapi s_enable_trace(thid_t tid, bool enable, int tracebit)
{
  msg(API_RECV "%s(tid=%d, enable=%s, tracebit=%d)\n", __func__, tid, enable ? "true" : "false", tracebit);
  auto rc = g_dbgmod.dbg_enable_trace(tid, enable, tracebit);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
bool idaapi s_is_tracing_enabled(thid_t tid, int tracebit)
{
  msg(API_RECV "%s(tid=%d, tracebit=%d)\n", __func__, tid, tracebit);
  auto rc = g_dbgmod.dbg_is_tracing_enabled(tid, tracebit);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
int idaapi s_rexec(const char *cmdline)
{
  msg(API_RECV "%s(cmdline=%s)\n", __func__, cmdline);
  auto rc = g_dbgmod.dbg_rexec(cmdline);
  msg(API_RESP "%s -> %d\n", __func__, rc);
  return rc;
}

//--------------------------------------------------------------------------
void idaapi s_get_debapp_attrs(debapp_attrs_t *out_pattrs)
{
  g_dbgmod.dbg_get_debapp_attrs(out_pattrs);
  msg(API_RECV "%s(out_pattrs={cbsize=%d, platform=%s})\n", __func__, out_pattrs->cbsize, out_pattrs->platform.c_str());
}

//--------------------------------------------------------------------------
bool idaapi s_get_srcinfo_path(qstring *path, ea_t base)
{
  msg(API_RECV "%s(path=%s, base=0x%08llX)\n", __func__, path->c_str(), base);
  auto rv = g_dbgmod.dbg_get_srcinfo_path(path, base);
  if (rv)
    msg(API_RESP "%s -> path=%s\n", __func__, path->c_str());
  else
    msg(API_RESP "%s -> false\n", __func__);
  return rv;
}

//--------------------------------------------------------------------------
#ifdef REMOTE_DEBUGGER
bool s_close_remote()
{
  return g_dbgmod.close_remote();
}
bool s_open_remote(const char *hostname, int port_number, const char *password)
{
  return g_dbgmod.open_remote(hostname, port_number, password);
}
#else
bool s_open_remote(const char *, int, const char *)
{
  return true;
}

bool s_close_remote(void)
{
  return true;
}

#endif

//--------------------------------------------------------------------------
// Local debuggers must call setup_lowcnd_regfuncs() in order to handle
// register read/write requests from low level bpts.
void init_dbg_idcfuncs(bool init)
{
#if !defined(ENABLE_LOWCNDS) ||                 \
     defined(REMOTE_DEBUGGER) ||                \
     DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  qnotused(init);
#else
  setup_lowcnd_regfuncs(init ? idc_get_reg_value : NULL,
                        init ? idc_set_reg_value : NULL);
#endif
}
