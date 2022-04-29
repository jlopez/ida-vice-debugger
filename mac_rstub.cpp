/*
        This is the MAC OS X x86 user land debugger entry point file
*/
#ifndef __GNUC__
//lint -esym(750, __LITTLE_ENDIAN__) not referenced
#define __LITTLE_ENDIAN__
#endif
//#define __inline__ inline
#define REMOTE_DEBUGGER
#define RPC_CLIENT

static const char wanted_name[] = "Vice debugger";
#define DEBUGGER_NAME  "vice"
#define PROCESSOR_NAME "M6502"
#define DEFAULT_PLATFORM_NAME "vice"
#define TARGET_PROCESSOR PLFM_6502
#define DEBUGGER_ID_VICE                          6510 ///< Vice
#define DEBUGGER_ID    DEBUGGER_ID_VICE
#define DEBUGGER_RESMOD (DBG_RESMOD_STEP_INTO)

#define HAVE_APPCALL
#define S_FILETYPE     f_MACHO

#include <pro.h>
#include <idp.hpp>
#include <idd.hpp>
#include <ua.hpp>
#include <range.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "rpc_client.h"
#include "rpc_debmod.h"
#include "tcpip.h"

rpc_debmod_t g_dbgmod(DEFAULT_PLATFORM_NAME);
#include "common_stub_impl.cpp"

#include "pc_local_impl.cpp"
#include "mac_local_impl.cpp"
#include "common_local_impl.cpp"
