#ifndef __CONSTS__
#define __CONSTS__

#import "colors.h"

#define SGR_RESET "\x1B[0m"
#define API_RECV FG_87_SEA_BLUE "API_RECV " SGR_RESET
#define API_RESP FG_87_SEA_BLUE "API_RESP " SGR_RESET
#define API_HEAD "         "

//
//      This file contains definition and consts shared among all debugger clients and servers
//
//

#define TIMEOUT         (1000/25)       // in milliseconds, timeout for polling
#define TIMEOUT_INFINITY -1
#define RECV_TIMEOUT_PERIOD (10000)     // in milliseconds, timeout for recv()

// the idarpc_stream_struct_t structure is not defined.
// it is used as an opaque type provided by the transport level.
// the transport level defines its own local type for it.
typedef struct idarpc_stream_struct_t idarpc_stream_t;

// bidirectional codes (client <-> server)
enum BinaryMonitorCommand : uchar
{
  MON_CMD_INVALID                   = 0x00,

  MON_CMD_MEM_GET                   = 0x01,
  MON_CMD_MEM_SET                   = 0x02,

  MON_CMD_CHECKPOINT_GET            = 0x11,
  MON_CMD_CHECKPOINT_SET            = 0x12,
  MON_CMD_CHECKPOINT_DELETE         = 0x13,
  MON_CMD_CHECKPOINT_LIST           = 0x14,
  MON_CMD_CHECKPOINT_TOGGLE         = 0x15,

  MON_CMD_CONDITION_SET             = 0x22,

  MON_CMD_REGISTERS_GET             = 0x31,
  MON_CMD_REGISTERS_SET             = 0x32,

  MON_CMD_DUMP                      = 0x41,
  MON_CMD_UNDUMP                    = 0x42,

  MON_CMD_RESOURCE_GET              = 0x51,
  MON_CMD_RESOURCE_SET              = 0x52,

  MON_CMD_ADVANCE_INSTRUCTIONS      = 0x71,
  MON_CMD_KEYBOARD_FEED             = 0x72,
  MON_CMD_EXECUTE_UNTIL_RETURN      = 0x73,

  MON_CMD_PING                      = 0x81,
  MON_CMD_BANKS_AVAILABLE           = 0x82,
  MON_CMD_REGISTERS_AVAILABLE       = 0x83,
  MON_CMD_DISPLAY_GET               = 0x84,
  MON_CMD_VICE_INFO                 = 0x85,

  MON_CMD_PALETTE_GET               = 0x91,

  MON_CMD_JOYPORT_SET               = 0xa2,

  MON_CMD_USERPORT_SET              = 0xb2,

  MON_CMD_EXIT                      = 0xaa,
  MON_CMD_QUIT                      = 0xbb,
  MON_CMD_RESET                     = 0xcc,
  MON_CMD_AUTOSTART                 = 0xdd,
};

enum BinaryMonitorErrorCode : uchar {
  MON_ERR_OK                        = 0x00,
  MON_ERR_OBJECT_MISSING            = 0x01,
  MON_ERR_INVALID_MEMSPACE          = 0x02,
  MON_ERR_CMD_INVALID_LENGTH        = 0x80,
  MON_ERR_INVALID_PARAMETER         = 0x81,
  MON_ERR_CMD_INVALID_API_VERSION   = 0x82,
  MON_ERR_CMD_INVALID_TYPE          = 0x83,
  MON_ERR_CMD_FAILURE               = 0x8f,
};

enum BinaryMonitorCommandResponse : uchar
{
  MON_RESPONSE_INVALID              = 0x00,
  MON_RESPONSE_MEM_GET              = 0x01,
  MON_RESPONSE_MEM_SET              = 0x02,

  MON_RESPONSE_CHECKPOINT_INFO      = 0x11,

  MON_RESPONSE_CHECKPOINT_DELETE    = 0x13,
  MON_RESPONSE_CHECKPOINT_LIST      = 0x14,
  MON_RESPONSE_CHECKPOINT_TOGGLE    = 0x15,

  MON_RESPONSE_CONDITION_SET        = 0x22,

  MON_RESPONSE_REGISTER_INFO        = 0x31,

  MON_RESPONSE_DUMP                 = 0x41,
  MON_RESPONSE_UNDUMP               = 0x42,

  MON_RESPONSE_RESOURCE_GET         = 0x51,
  MON_RESPONSE_RESOURCE_SET         = 0x52,

  MON_RESPONSE_JAM                  = 0x61,
  MON_RESPONSE_STOPPED              = 0x62,
  MON_RESPONSE_RESUMED              = 0x63,

  MON_RESPONSE_ADVANCE_INSTRUCTIONS = 0x71,
  MON_RESPONSE_KEYBOARD_FEED        = 0x72,
  MON_RESPONSE_EXECUTE_UNTIL_RETURN = 0x73,

  MON_RESPONSE_PING                 = 0x81,
  MON_RESPONSE_BANKS_AVAILABLE      = 0x82,
  MON_RESPONSE_REGISTERS_AVAILABLE  = 0x83,
  MON_RESPONSE_DISPLAY_GET          = 0x84,
  MON_RESPONSE_VICE_INFO            = 0x85,

  MON_RESPONSE_PALETTE_GET          = 0x91,

  MON_RESPONSE_JOYPORT_SET          = 0xa2,

  MON_RESPONSE_USERPORT_SET         = 0xb2,

  MON_RESPONSE_EXIT                 = 0xaa,
  MON_RESPONSE_QUIT                 = 0xbb,
  MON_RESPONSE_RESET                = 0xcc,
  MON_RESPONSE_AUTOSTART            = 0xdd,
};

enum BinaryMonitorMemSpace : uchar
{
  kMemSpaceMainMemory = 0,
  kMemSpaceDrive8 = 1,
  kMemSpaceDrive9 = 2,
  kMemSpaceDrive10 = 3,
  kMemSpaceDrive11 = 4,
};

const int kCpuOperationNone = 0;
const int kCpuOperationLoad = 1;
const int kCpuOperationStore = 2;
const int kCpuOperationExec = 4;

enum BinaryMonitorBankID : uint8
{
  CPU = 0,
  RAM = 1,
  ROM = 2,
  IO  = 3,
  CART = 4
};

enum BinaryMonitorResetType: uchar
{
  kSoftReset = 0,
  kHardReset = 1,
  kResetDrive8 = 8,
  kResetDrive9 = 9,
  kResetDrive10 = 10,
  kResetDrive11 = 11,
};

template <typename T> class DeductTypeCatcher {
public:
    DeductTypeCatcher() { T t = (void***)0; }
};

#define SHOW_DEDUCT_TYPE(t)     DeductTypeCatcher<decltype(t)> __catcher__;

#define RPC_OK    0      // response: function call succeeded
#define RPC_UNK   1      // response: unknown function code
#define RPC_MEM   2      // response: no memory

#define RPC_OPEN  3      // server->client: i'm ready, the very first packet

#define RPC_EVENT 4      // server->client: debug event ready, followed by debug_event
#define RPC_EVOK  5      // client->server: event processed (in response to RPC_EVENT)
// we need EVOK to handle the situation when the debug
// event was detected by the server during polling and
// was sent to the client using RPC_EVENT but client has not received it yet
// and requested GET_DEBUG_EVENT. In this case we should not
// call remote_get_debug_event() but instead force the client
// to use the event sent by RPC_EVENT.
// In other words, if the server has sent RPC_EVENT but has not
// received RPC_EVOK, it should fail all GET_DEBUG_EVENTS.

// client->server codes
#define RPC_INIT                      10
#define RPC_TERM                      11
#define RPC_GET_PROCESSES             12
#define RPC_START_PROCESS             13
#define RPC_EXIT_PROCESS              14
#define RPC_ATTACH_PROCESS            15
#define RPC_DETACH_PROCESS            16
#define RPC_GET_DEBUG_EVENT           17
#define RPC_PREPARE_TO_PAUSE_PROCESS  18
#define RPC_STOPPED_AT_DEBUG_EVENT    19
#define RPC_CONTINUE_AFTER_EVENT      20
#define RPC_TH_SUSPEND                21
#define RPC_TH_CONTINUE               22
#define RPC_SET_RESUME_MODE           23
#define RPC_GET_MEMORY_INFO           24
#define RPC_READ_MEMORY               25
#define RPC_WRITE_MEMORY              26
#define RPC_UPDATE_BPTS               27
#define RPC_UPDATE_LOWCNDS            28
#define RPC_EVAL_LOWCND               29
#define RPC_ISOK_BPT                  30
#define RPC_READ_REGS                 31
#define RPC_WRITE_REG                 32
#define RPC_GET_SREG_BASE             33
#define RPC_SET_EXCEPTION_INFO        34

#define RPC_OPEN_FILE                 35
#define RPC_CLOSE_FILE                36
#define RPC_READ_FILE                 37
#define RPC_WRITE_FILE                38
#define RPC_IOCTL                     39 // both client and the server may send this packet
#define RPC_UPDATE_CALL_STACK         40
#define RPC_APPCALL                   41
#define RPC_CLEANUP_APPCALL           42
#define RPC_REXEC                     43
#define RPC_GET_SCATTERED_IMAGE       44
#define RPC_GET_IMAGE_UUID            45
#define RPC_GET_SEGM_START            46

// server->client codes
#define RPC_SET_DEBUG_NAMES           50
#define RPC_SYNC_STUB                 51
#define RPC_ERROR                     52
#define RPC_MSG                       53
#define RPC_WARNING                   54
#define RPC_HANDLE_DEBUG_EVENT        55
#define RPC_REPORT_IDC_ERROR          56

#pragma pack(push, 1)

struct PACKED mon_request_t
{
  uchar stx;
  uchar api_id;
  uint32 body_length;
  uint32 request_id;
  BinaryMonitorCommand command;
  uchar body[0];
};

struct PACKED mon_response_t
{
  uchar stx;
  uchar api_id;
  uint32 body_length;
  BinaryMonitorCommandResponse response_type;
  uchar error_code;
  uint32 request_id;
  uchar body[0];
};

struct PACKED rpc_packet_t
{                        // fields are always sent in the network order
  uint32 length;         // length of the packet (do not count length & code)
  uchar code;            // function code
};
CASSERT(sizeof(rpc_packet_t) == 5);
#pragma pack(pop)

// Error reporting functions
class rpc_engine_t;
AS_PRINTF(2, 0) void    dmsg(rpc_engine_t *, const char *format, va_list va);
AS_PRINTF(2, 0) void    derror(rpc_engine_t *, const char *format, va_list va);
AS_PRINTF(2, 0) void    dwarning(rpc_engine_t *, const char *format, va_list va);
AS_PRINTF(3, 0) ssize_t dvmsg(int code, rpc_engine_t *ud, const char *format, va_list va);

// We use this to declare reporting functions with a given user data
#define DECLARE_UD_REPORTING(fnc, rpc) \
  AS_PRINTF(2, 3) void d##fnc(const char *format, ...) \
  { \
    va_list va; \
    va_start(va, format); \
    ::d##fnc(rpc, format, va); \
    va_end(va); \
  }

class idc_value_t;
error_t idaapi idc_get_reg_value(idc_value_t *argv, idc_value_t *r);
error_t idaapi idc_set_reg_value(idc_value_t *argv, idc_value_t *r);
void report_idc_error(rpc_engine_t *rpc, ea_t ea, error_t code, ssize_t errval, const char *errprm);

// IDC function name that is exported by a debugger module
// to allow scripts to send debugger commands
#define IDC_SENDDBG_CMD "send_dbg_command"
#define IDC_READ_MSR    "read_msr"
#define IDC_WRITE_MSR   "write_msr"
#define IDC_STEP_BACK   "step_back"
#define IDC_SET_TEV     "set_current_tev"
#define IDC_GET_TEV     "get_current_tev"

// A macro to convert a pointer to ea_t without sign extension.
#define EA_T(ptr) (ea_t)(size_t)(ptr)

#endif
