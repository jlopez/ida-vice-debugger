//
// This file is included from other files, do not directly compile it.
// It contains the debugger_t structure definition and a few other helper functions
//

#include <loader.hpp>
#include <segregs.hpp>
#include "consts.h"

bool plugin_inited;
bool debugger_inited;

#if TARGET_PROCESSOR == PLFM_386
  #define REGISTERS                x86_registers
  #define REGISTERS_SIZE           qnumber(x86_registers)
  #define REGISTER_CLASSES         x86_register_classes
  #define REGISTER_CLASSES_DEFAULT X86_RC_GENERAL
  #define READ_REGISTERS           x86_read_registers
  #define WRITE_REGISTER           x86_write_register
  #if DEBUGGER_ID != DEBUGGER_ID_GDB_USER && DEBUGGER_ID != DEBUGGER_ID_ARM_IPHONE_USER
    #define is_valid_bpt           is_x86_valid_bpt
  #endif
  #define BPT_CODE                 X86_BPT_CODE
  #define BPT_CODE_SIZE            X86_BPT_SIZE
#elif TARGET_PROCESSOR == PLFM_ARM
  #define REGISTERS                arm_registers
  #define REGISTERS_SIZE           qnumber(arm_registers)
  #define REGISTER_CLASSES         arm_register_classes
  #define REGISTER_CLASSES_DEFAULT ARM_RC_GENERAL
  #define READ_REGISTERS           arm_read_registers
  #define WRITE_REGISTER           arm_write_register
  #if DEBUGGER_ID != DEBUGGER_ID_GDB_USER && DEBUGGER_ID != DEBUGGER_ID_ARM_IPHONE_USER
    #define is_valid_bpt           is_arm_valid_bpt
  #endif
  #define BPT_CODE                 ARM_BPT_CODE
  #define BPT_CODE_SIZE            ARM_BPT_SIZE
#elif TARGET_PROCESSOR == PLFM_DALVIK
  #define BPT_CODE                 { 0 }
  #define BPT_CODE_SIZE            0
  #define READ_REGISTERS           s_read_registers
  #define WRITE_REGISTER           s_write_register
  #define is_valid_bpt             is_dalvik_valid_bpt
#elif TARGET_PROCESSOR == PLFM_6502
  #define REGISTERS                m6502_registers
  #define REGISTERS_SIZE           qnumber(x86_registers)
  #define REGISTER_CLASSES         m6502_register_classes
  #define REGISTER_CLASSES_DEFAULT M6502_RC_GENERAL
  #define READ_REGISTERS           x86_read_registers
  #define WRITE_REGISTER           x86_write_register
  #if DEBUGGER_ID != DEBUGGER_ID_GDB_USER && DEBUGGER_ID != DEBUGGER_ID_ARM_IPHONE_USER
    #define is_valid_bpt           is_x86_valid_bpt
  #endif
  #define BPT_CODE                 X86_BPT_CODE
  #define BPT_CODE_SIZE            X86_BPT_SIZE
#else
  #error This processor is not supported yet
#endif

static const uchar bpt_code[] = BPT_CODE;

//--------------------------------------------------------------------------
int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
  msg(API_RECV "%s(type=0x%02X, ea=0x%08llX, len=0x%X)\n", __func__, type, ea, len);
  auto rv = s_is_ok_bpt(type, ea, len);
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

//--------------------------------------------------------------------------
// For ARM, we have to set the low bit of the address to 1 for thumb mode
#if DEBUGGER_ID == DEBUGGER_ID_ARM_LINUX_USER
static int idaapi arm_update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  // This function is called from debthread, but to use get_sreg() we must
  // switch to the mainthread
  struct ida_local arm_bptea_fixer_t : public exec_request_t
  {
    update_bpt_info_t *bpts;
    update_bpt_info_t *e;
    qvector<ea_t *> thumb_mode;
    virtual int idaapi execute(void)
    {
      for ( update_bpt_info_t *b=bpts; b != e; b++ )
      {
        if ( b->type == BPT_SOFT && get_sreg(b->ea, ARM_T) == 1 )
        {
          b->ea++; // odd address means that thumb bpt must be set
          thumb_mode.push_back(&b->ea);
        }
      }
      return 0;
    }
    arm_bptea_fixer_t(update_bpt_info_t *p1, update_bpt_info_t *p2)
      : bpts(p1), e(p2) {}
  };
  arm_bptea_fixer_t abf(bpts, bpts+nadd);
  execute_sync(abf, MFF_READ);

  int ret = s_update_bpts(bpts, nadd, ndel);

  // reset the odd bit because the addresses are required by the caller
  for ( int i=0; i < abf.thumb_mode.size(); i++ )
    (*abf.thumb_mode[i])--;

  return ret;
}
#define s_update_bpts arm_update_bpts
#endif

//--------------------------------------------------------------------------
/// Add/del breakpoints.
/// bpts array contains nadd bpts to add, followed by ndel bpts to del.
/// This function is called from debthread.
/// \return number of successfully modified bpts, -1 if network error
static int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
  msg(API_RECV "%s(nadd=%d, ndel=%d)\n", __func__, nadd, ndel);
  auto b = bpts;
  for (auto n = 0; n != nadd + ndel; ++n, ++b) {
    msg(API_HEAD "%s bpt={ea=0x%08llX, type=0x%02X, size=0x%04X, code=%d}\n",
        n < nadd ? "set" : "del", b->ea, b->type, b->size, b->code);
  }
  int ret = s_update_bpts(bpts, nadd, ndel);
  msg(API_RESP "%s -> %d\n", __func__, ret);
  return ret;
}

//--------------------------------------------------------------------------
static void idaapi stopped_at_debug_event(bool dlls_added)
{
  msg(API_RECV "%s(dlls_added=%s)\n", __func__, dlls_added ? "true" : "false");
  s_stopped_at_debug_event();
}

//--------------------------------------------------------------------------
#ifndef REMOTE_DEBUGGER
// another copy of this function (for remote debugging) is defined in rpc_server.cpp
int send_ioctl(
        void *,
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize)
{
  return g_dbgmod.handle_ioctl(fn, buf, size, poutbuf, poutsize);
}
#endif

//--------------------------------------------------------------------------
THREAD_SAFE int debmod_t::send_debug_names_to_ida(
        ea_t *addrs,
        const char *const *names,
        int qty)
{
  return ::send_debug_names_to_ida(addrs, names, qty);
}

//---------------------------------------------------------------------------
THREAD_SAFE int send_debug_names_to_ida(
        ea_t *addrs,
        const char *const *names,
        int qty)
{
  struct debug_name_handler_t : public exec_request_t
  {
    ea_t *addrs;
    const char *const *names;
    int qty;
    debug_name_handler_t(ea_t *_addrs, const char *const *_names, int _qty)
      : addrs(_addrs), names(_names), qty(_qty) {}
    int idaapi execute(void)
    {
      set_arm_thumb_modes(addrs, qty);
      return set_debug_names(addrs, names, qty);
    }
  };
  debug_name_handler_t dnh(addrs, names, qty);
  return execute_sync(dnh, MFF_WRITE);
}

//--------------------------------------------------------------------------
THREAD_SAFE int debmod_t::send_debug_event_to_ida(
        const debug_event_t *ev,
        int rqflags)
{
  return ::send_debug_event_to_ida(ev, rqflags);
}

//---------------------------------------------------------------------------
THREAD_SAFE int send_debug_event_to_ida(
        const debug_event_t *ev,
        int rqflags)
{
  return handle_debug_event(ev, rqflags);
}

//--------------------------------------------------------------------------
#if TARGET_PROCESSOR != PLFM_ARM
void set_arm_thumb_modes(ea_t * /*addrs*/, int /*qty*/)
{
}
#endif

//--------------------------------------------------------------------------
// installs or uninstalls debugger specific idc functions
bool add_idc_funcs(const ext_idcfunc_t efuncs[], size_t nfuncs, bool reg)
{
  if ( reg )
  {
    for ( int i=0; i < nfuncs; i++ )
      if ( !add_idc_func(efuncs[i]) )
        return false;
  }
  else
  {
    for ( int i=0; i < nfuncs; i++ )
      if ( !del_idc_func(efuncs[i].name) )
        return false;
  }
  return true;
}

//--------------------------------------------------------------------------
const char *get_event_name(event_id_t eid) {
  static const char *event_id_names[] = {
    "NO_EVENT",
    "PROCESS_START",
    "PROCESS_EXIT",
    "THREAD_START",
    "THREAD_EXIT",
    "BREAKPOINT",
    "STEP",
    "EXCEPTION",
    "LIBRARY_LOAD",
    "LIBRARY_UNLOAD",
    "INFORMATION",
    "SYSCALL",
    "WINMESSAGE",
    "PROCESS_ATTACH",
    "PROCESS_DETACH",
    "PROCESS_SUSPEND",
    "TRACE_FULL",
    "UNKNOWN",
  };
  auto bit = ffs(eid);
  return event_id_names[std::min(17, bit)];
}

//--------------------------------------------------------------------------
static bool idaapi init_debugger(
        const char *hostname,
        int port_num,
        const char *password)
{
  msg(API_RECV "%s(hostname=%s, port_num=%d, password=%s) debug=0x%04X\n", __func__, hostname, port_num, password, debug);
  s_set_debugging((debug & IDA_DEBUG_DEBUGGER) != 0);

  if ( !s_open_remote(hostname, port_num, password) )
    return false;

  int code = s_init();
  // network error?
  if ( code <= 0 )
  {
    s_close_remote();
    return false;
  }

  //debugger.get_processes  = (code & DBG_HAS_PROCGETINFO) != 0 ? s_get_processes  : NULL;
  //debugger.detach_process = (code & DBG_HAS_DETACHPROC)  != 0 ? s_detach_process : NULL;
  debugger_inited = true;
#ifdef WINCE_DEBUGGER
  slot = BADADDR;
  wince_load_options();
#endif
  processor_specific_init();
  register_idc_funcs(true);
  init_dbg_idcfuncs(true);
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
  install_x86seh_menu();
#endif
  return true;
}

//--------------------------------------------------------------------------
static bool idaapi term_debugger(void)
{
  msg(API_RECV "%s()", __func__);
  if ( debugger_inited )
  {
    debugger_inited = false;
#if DEBUGGER_ID == DEBUGGER_ID_X86_IA32_WIN32_USER || DEBUGGER_ID == DEBUGGER_ID_X86_IA32_BOCHS
    remove_x86seh_menu();
#endif
    init_dbg_idcfuncs(false);
    register_idc_funcs(false);
    processor_specific_term();
    g_dbgmod.dbg_term();
    return s_close_remote();
  }
  return false;
}

//--------------------------------------------------------------------------
// Initialize debugger plugin
static int do_init(void);
static int idaapi init(void)
{
  msg(API_RECV "%s()\n", __func__);
  auto rv = do_init();
  msg(API_RESP "%s -> %d\n", __func__, rv);
  return rv;
}

static int do_init(void)
{
#if !defined(__X64__) && DEBUGGER_ID != DEBUGGER_ID_X86_IA32_BOCHS \
 && DEBUGGER_ID != DEBUGGER_ID_TRACE_REPLAYER
  // Cannot debug 64-bit files locally in 32-bit IDA
  if ( inf.is_64bit() && !debugger.is_remote() )
    return PLUGIN_SKIP;
#endif
  if ( init_plugin() )
  {
    dbg = &debugger;
    plugin_inited = true;
    return PLUGIN_KEEP;
  }
  return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
  msg(API_RECV "%s()\n", __func__);
  if ( plugin_inited )
  {
    term_plugin();
    plugin_inited = false;
  }
  // we're being unloaded, clear the 'dbg' pointer if it's ours
  if ( dbg == &debugger )
    dbg = NULL;
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static bool idaapi run(size_t arg)
{
#ifdef HAVE_PLUGIN_RUN
  plugin_run(int(arg));
#else
  qnotused(arg);
#endif
  return true;
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

#ifdef REMOTE_DEBUGGER
#  ifndef S_OPEN_FILE
#    define S_OPEN_FILE  s_open_file
#  endif
#  ifndef S_CLOSE_FILE
#    define S_CLOSE_FILE s_close_file
#  endif
#  ifndef S_READ_FILE
#    define S_READ_FILE  s_read_file
#  endif
#  ifndef S_WRITE_FILE
#    define S_WRITE_FILE s_write_file
#  endif
#else
#  define S_OPEN_FILE  NULL
#  define S_CLOSE_FILE NULL
#  define S_READ_FILE  NULL
#  define S_WRITE_FILE NULL
#endif

#ifndef GET_DEBMOD_EXTS
#  define GET_DEBMOD_EXTS NULL
#endif

#ifndef HAVE_UPDATE_CALL_STACK
#  define UPDATE_CALL_STACK NULL
#else
#  define UPDATE_CALL_STACK s_update_call_stack
#endif

#ifndef HAVE_APPCALL
#  define APPCALL NULL
#  define CLEANUP_APPCALL NULL
#else
#  define APPCALL s_appcall
#  define CLEANUP_APPCALL s_cleanup_appcall
#endif

#ifndef S_MAP_ADDRESS
#  define S_MAP_ADDRESS NULL
#endif

#ifndef SET_DBG_OPTIONS
#  define SET_DBG_OPTIONS NULL
#endif

#ifndef S_FILETYPE
#  define S_FILETYPE 0
#endif

#ifndef HAVE_GET_SRCINFO_PATH
#  define GET_SRCINFO_PATH NULL
#else
#  define GET_SRCINFO_PATH s_get_srcinfo_path
#endif

// wince has no single step mechanism (except Symbian TRK, which provides support for it)
#if TARGET_PROCESSOR == PLFM_ARM && DEBUGGER_ID != DEBUGGER_ID_ARM_EPOC_USER
#  define S_SET_RESUME_MODE NULL
#else
#  define S_SET_RESUME_MODE s_set_resume_mode
#endif
#ifndef DEBUGGER_RESMOD
#  define DEBUGGER_RESMOD 0
#endif
debugger_t debugger =
{
  IDD_INTERFACE_VERSION,
  DEBUGGER_NAME,
  DEBUGGER_ID,
  PROCESSOR_NAME,

  DBG_FLAG_REMOTE |
  DBG_FLAG_CAN_CONT_BPT |
  DBG_FLAG_SAFE |
  DBG_FLAG_NOSTARTDIR |
  DBG_FLAG_NOPARAMETERS |
  DBG_FLAG_NOPASSWORD |
  DBG_FLAG_LOWCNDS |
  DBG_FLAG_DEBTHREAD |
  DBG_FLAG_ANYSIZE_HWBPT,

  m6502_register_classes,
  M6502_RC_GENERAL,
  m6502_registers,
  10,

  MEMORY_PAGE_SIZE,

  bpt_code,
  sizeof(bpt_code),
  S_FILETYPE,
  DBG_RESMOD_STEP_OUT | DBG_RESMOD_STEP_INTO | DBG_RESMOD_STEP_OVER,

  init_debugger,
  term_debugger,

  s_get_processes,
  s_start_process,
  s_attach_process,
  s_detach_process,
  rebase_if_required_to,
  s_prepare_to_pause_process,
  s_exit_process,

  s_get_debug_event,
  s_continue_after_event,
  s_set_exception_info,
  stopped_at_debug_event,

  s_thread_suspend,
  s_thread_continue,
  s_set_resume_mode,
  x86_read_registers,
  x86_write_register,
  s_thread_get_sreg_base,

  s_get_memory_info,
  s_read_memory,
  s_write_memory,

  is_ok_bpt,
  update_bpts,
  s_update_lowcnds,
  s_open_file,
  s_close_file,
  s_read_file,
  nullptr, // s_map_address,
  s_set_dbg_options,
  s_get_debmod_extensions,
  s_update_call_stack,
  s_appcall,
  s_cleanup_appcall,
  s_eval_lowcnd,
  s_write_file,
  s_ioctl,
  s_enable_trace,
  s_is_tracing_enabled,
  s_rexec,
  s_get_debapp_attrs,
  s_get_srcinfo_path,
};

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE|PLUGIN_DBG, // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  comment,              // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
