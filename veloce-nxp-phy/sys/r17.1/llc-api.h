// No doxygen 'group' header because this file is included by both user & kernel implementations

//------------------------------------------------------------------------------
// Copyright (c) 2017 Cohda Wireless Pty Ltd
//------------------------------------------------------------------------------

#ifndef LINUX__COHDA__LLC__LLC_API_H
#define LINUX__COHDA__LLC__LLC_API_H

//------------------------------------------------------------------------------
// Included headers
//------------------------------------------------------------------------------

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // for memcpy

// Limits of integral types
#ifndef INT8_MIN
#define INT8_MIN               (-128)
#endif
#ifndef INT16_MIN
#define INT16_MIN              (-32767-1)
#endif
#ifndef INT16_MAX
#define INT16_MAX              (32767)
#endif

#else
#include <stdint.h>
#include <string.h> // For memcpy()
#endif

#ifdef __cplusplus
extern "C"
{
#endif

//------------------------------------------------------------------------------
// Macros & Constants
//------------------------------------------------------------------------------

/// Major version of this API.  Mismatch between kernel and SAF5x00 firmware
/// results in blocked communications
#define LLC_API_VERSION_MAJOR 6U

/// Minor version/iteration of this API.  Mismatch between kernel and SAF5x00
/// firmware results in warning only.
#define LLC_API_VERSION_MINOR 0U

/// Version of the calibration data structure provided in this header
#define CALIBRATION_VERSION 3U

/// MKx magic value
#define MKX_API_MAGIC (0xC0DAU)

/// The size of the Address Matching Table
#define AMS_TABLE_COUNT 8U

/// The number of channels that certain calibration is performed on (168-184)
/// Indices are 0:168, 1:170, 2:172, 3:174, 4:176, 5:178, 6:180, 7:182, 8:184
/// 9:All Other Channels
#define CAL_CHANNEL_COUNT (((184U - 168U)/2U) + 1U + 1U)

/// Number of calibration points (inc. line) for the power detector model
#define CAL_POINT_COUNT 2U

/// Log message maximum number of allowed data parameters
#define MAX_NUM_LOG_PARAMETERS                          16U
/// Log message maximum number of allowed text bytes
#define MAX_LOG_TEXT_BYTES                              48UL

/// Rename of inline
#ifndef INLINE
#define INLINE __inline
#endif

//------------------------------------------------------------------------------
// Type definitions
//------------------------------------------------------------------------------

/**
 * @section llc_remote Remote LLC Module
 *
 * LLCRemote implements a mechanism to allow the MKx Modem to be used as a
 * remote MAC to a Linux Host machine.
 *
 * @verbatim
                       Source provided -> +----------------+
   +-----------------+                    |  llc debug app |
   |   Stack / Apps  |                    +-------*--------+
   +---*-------*-----+                            |                  User Space
 ------|-------|----------------------------------|---------------------------
       | ioctl | socket(s)                        | socket         Kernel Space
     +-*-------*---+                              |
     |  simTD API  | (optional binary)            |
     +------*------+                              |
            | API (MKx_* functions)               |
     +------*------+                              |
     |  LLCRemote  +------------------------------+
     |             |<- Source code provided
     +--*-------*--+
        | USB   | Ethernet (MKxIF_* structures)
    +---*-+ +---*----+
    | USB | | TCP/IP |
    +-----+ +--------+                                         Client side (uP)
 -----------------------------------------------------------------------------
 +---------------------+ +---------------------+              Server Side (SDR)
 |        WMAC         | |   C2X Security      |
 +---------------------+ +---------------------+
 |     802.11p MAC     |
 +---------------------+
 |     802.11p PHY     |
 +---------------------+
 @endverbatim
 *
 * @subsection llc_remote_design LLCRemote MAC Design
 *
 * The LLCRemote module communicates between Server and Client via two USB bulk
 * endpoints or two UDP sockets.
 */

/// Types for the LLCRemote message transfers
typedef enum
{
  /// LLC API Version message type
  MKXIF_APIVERSION  = 0U,
  /// A transmit packet (message data is @ref tMKxTxPacket)
  MKXIF_TXPACKET    = 1,
  /// A received packet (message data is @ref tMKxRxPacket)
  MKXIF_RXPACKET    = 2,
  /// New UTC Time (message data is @ref tMKxSetTSF)
  MKXIF_SET_TSF     = 3,
  /// Transmitted packet event (message data is @ref tMKxTxEventData)
  MKXIF_TXEVENT     = 4,
  /// Radio config for Radio A (message data is @ref tMKxRadioConfig)
  MKXIF_RADIOACFG   = 5,
  /// Radio config for Radio B (message data is @ref tMKxRadioConfig)
  MKXIF_RADIOBCFG   = 6,
  /// Radio A statistics (message data is @ref tMKxRadioStats)
  MKXIF_RADIOASTATS = 7,
  /// Radio B statistics (message data is @ref tMKxRadioStats)
  MKXIF_RADIOBSTATS = 8,
  /// Flush a single queue or all queues (message data is @ref tMKxFlushQueue)
  MKXIF_FLUSHQ      = 9,
  /// A generic debug container.
  MKXIF_DEBUG       = 10,
  /// C2XSEC message (message data is @ref tMKxC2XSec)
  MKXIF_C2XSEC      = 11,
  /// Calibration config message (message data is @ref tMKxCalibrationData)
  MKXIF_CALIBRATION = 12,
  /// Temperature measurement message (message data is @ref tMKxTemp)
  MKXIF_TEMP        = 13,
  /// Read the current UTC Time (message data is @ref tMKxGetTSF)
  MKXIF_GET_TSF     = 14,
  /// Auxiliary ADC message (message data is @ref tMKxAuxADCData)
  MKXIF_AUXADC      = 15,
  /// Auxiliary ADC config message (message data is @ref tMKxAuxADCConfigData)
  MKXIF_AUXADCCFG   = 16,
  /// Error event message (errorcode is in Ret)
  MKXIF_ERROR       = 17,
  /// Warning event message (errorcode is in Ret)
  MKXIF_WARNING     = 18,
  /// Log messages (debug messages sent from the SAF5x00, @ref tMKxLog)
  MKXIF_LOG         = 19,
  /// GPIO control messages (message data is @ref tMKxGPIO)
  MKXIF_GPIO        = 20,
  /// Warm reset instruction to the radio
  MKXIF_RESET       = 21,
  /// Host radio loopback message (message data is @ref tMKxLoopbackData)
  MKXIF_LOOPBACK    = 22,
  /// Fault message (message data is @ref tMKxFaultData)(SAF5400 only)
  MKXIF_FAULT       = 23,
  /// Invalid message type, used for array dimensioning
  MKXIF_COUNT       = 24,
  /// Invalid message type, used for bounds checking
  MKXIF_MAX = MKXIF_COUNT - 1
} eMKxIFMsgType;
/// @copydoc eMKxIFMsgType
typedef uint16_t tMKxIFMsgType;

/// LLCRemote message header (LLC managed header)
/// Note the sequence number is overwritten by the LLC and the SAF5x00.  It is
/// used for detecting missing messages.  The reference number is used for
/// pairing request and indication messages.
typedef struct MKxIFMsg
{
  /// Message type
  tMKxIFMsgType Type;
  /// Length of the message, including the header itself
  uint16_t Len;
  /// Message sequence number
  uint16_t Seq;
  /// Message reference number
  uint16_t Ref;
  /// 32 bit alignment
  uint16_t Reserved;
  /// Return value, can be either @ref eMKxStatus or @ref eSAFErrorCode)
  int16_t Ret;
} __attribute__ ((packed)) tMKxIFMsg;

/**
 * @section llc_api MKx API
 *
 * This section provides an overview of the MKx WAVE MAC usage, in order to
 * clarify its functionality.
 *
 * @subsection general_usage General usage in a WSM/Proprietary Protocol System
 * (user-space implementation)
 *
 * Typical usage would be:
 * - Load the MKx LLC kernel module
 * - Open the MKx interface using the MKx_Init() function.
 * - Enable notifications by setting the pMKx->API.Callbacks.NotifInd() callback
 * - Enable packet reception by setting the pMKx->API.Callbacks.RxAlloc()
 *    pMKx->API.Callbacks.RxInd() and callbacks
 * - Enable transmit confirmations by setting the pMKx->API.Callbacks.TxCnf()
 *   callback
 * - Set the Radio A (CCH & SCH-A) parameters using the MKx_Config() function.
 * - Set the Radio B (CCH & SCH-B) parameters using the MKx_Config() function.
 * - Packets can be transmitted using the TxReq() function and the
 *   success/failure of the frame is indicated via the TxCnf() callback
 * - Packets received on either radio will be allocated with the RxAlloc()
 *   callback and delivered via the RxInd() callback
 * - When done, the MKx interface can be gracefully closed with MKx_Exit()
 *
 * @subsection channel_measurements Channel Measurements
 * - Statistics are updates are notified via the NotifInd() callback every 50ms
 * - Counters can be read directly from the MKx handle or using the
 *   MKx_GetStats() helper function
 *   - Channel busy ratio is provided in the per-channel statistics.
 *     This is the ratio of channel busy (virtual carrier sense is asserted)
 *     time to channel idle time.
 *     It is an 8-bit unsigned value, where 100% channel utilisation is
 *     indicated by a value of 255.
 *   - Average idle period power is provided in the per-channel statistics.
 *     This is the average RSSI recorded whilst the channel isn't busy
 *     (virtual carrier sense is not asserted).
 *
 * @subsection dual_channel_operation  Dual channel operation
 * When operating in a dual-radio configuration, it is possible to configure the
 * MAC channel access function to consider the state of the other radio channel
 * before making transmit decisions. The WMAC allows the following configuration
 * options for the channel access function when operating in a dual-radio system
 *
 * - No consideration of other radio. In this case, the radio will transmit
 *   without regard to the state of the other radio channel. The system will
 *   behave effectively as two independent radio systems.
 * - Tx inhibit. In this mode, the MAC will prevent this radio from transmitting
 *   while the other radio is transmitting. In this case, when the other radio
 *   is transmitting, the local radio behaves as if the local channel is busy.
 * - Rx inhibit. In this mode, the MAC will prevent this radio from
 *   transmitting while the other radio is actively receiving a frame. In this
 *   case, when the other radio is receiving, the local radio behaves as if the
 *   local channel is busy. This prevents transmissions from this radio from
 *   corrupting the reception of a frame on the other radio, tuned to a nearby
 *   radio channel (in particular when shared or co-located antennas are in use)
 * - TxRx inhibit. In this mode, the MAC will prevent this radio from
 *   transmitting while the other radio is either transmitting or receiving.
 *
 * In all cases, the transmission inhibit occurs at the MAC channel-access
 * level, so packets will not be dropped when transmission is inhibited, they
 * will simply be deferred.
 *
 */

/// Forward declaration of the MKx Handle
struct MKx;

/// MKx MLME interface return codes
typedef enum
{
  /// Success return code
  MKXSTATUS_SUCCESS = 0,
  // -1 to -255 reserved for @c errno values (see <errno.h>)
  /// Received MKXIF message with unexpected or invalid type
  MKXSTATUS_INVALID_MKXIF_TYPE                  = -256,
  /// Unspecified failure return code (catch-all)
  MKXSTATUS_FAILURE_INTERNAL_ERROR              = -257,
  /// Failure due to invalid MKx Handle
  MKXSTATUS_FAILURE_INVALID_HANDLE              = -258,
  /// Failure due to invalid length of the received message
  MKXSTATUS_FAILURE_INVALID_LENGTH              = -260,
  /// Failure due to invalid parameter setting
  MKXSTATUS_FAILURE_INVALID_PARAM               = -261,
  /// Auto-cal requested when radio is running auto-cal
  MKXSTATUS_FAILURE_AUTOCAL_REJECT_SIMULTANEOUS = -262,
  /// Auto-cal requested but radio is not configured
  MKXSTATUS_FAILURE_AUTOCAL_REJECT_UNCONFIGURED = -263,
  /// Failure due to invalid Calibration data
  MKXSTATUS_FAILURE_INVALID_CALIBRATION         = -264,
  /// Failure due to invalid version of the calibration data
  MKXSTATUS_FAILURE_INVALID_CALIBRATION_VERSION = -265,
  /// Failure due to invalid Radio
  MKXSTATUS_FAILURE_INVALID_RADIO               = -266,
  /// Message rejected as radio is currently in fail safe state
  MKXSTATUS_REJECTED_FAIL_SAFE_STATE            = -267,
  /// Radio config failed (likely to be a hardware fault) maximum
  MKXSTATUS_FAILURE_RADIOCONFIG_MAX             = -513,
  /// Rdio config failed (generic)
  MKXSTATUS_FAILURE_RADIOCONFIG_GENERIC         = -766,
  /// Radio config failed (likely to be a hardware fault) minimum
  MKXSTATUS_FAILURE_RADIOCONFIG_MIN             = -768,
  // Errors associated with Transmission
  /// Packet failed by exceeding Time To Live
  MKXSTATUS_TX_FAIL_TTL                         = -769,
  /// Packet failed by exceeding Max Retry count
  MKXSTATUS_TX_FAIL_RETRIES                     = -770,
  /// Packet failed because queue was full
  MKXSTATUS_TX_FAIL_QUEUEFULL                   = -771,
  /// Packet failed because requested radio is not present
  MKXSTATUS_TX_FAIL_RADIO_NOT_PRESENT           = -772,
  /// Packet failed because the frame was malformed
  MKXSTATUS_TX_FAIL_MALFORMED                   = -773,
  /// Packet failed in the PHY because the frame was malformed
  MKXSTATUS_TX_FAIL_MALFORMED_AT_PHY            = -774,
  /// Packet failed because requested radio is not present
  MKXSTATUS_TX_FAIL_RADIO_UNCONFIGURED          = -775,
  /// Packet failed because it was too long
  MKXSTATUS_TX_FAIL_PACKET_TOO_LONG             = -776,
  /// Packet failed because DMA failure
  MKXSTATUS_TX_FAIL_DMA                         = -777,
  /// Packet failed because of malformed antenna
  MKXSTATUS_TX_FAIL_INVALID_ANTENNA             = -778,
  /// Packet failed because radio is currently in fail safe state
  MKXSTATUS_TX_FAIL_FAIL_SAFE_STATE             = -779,
  /// Packet failed because of a host to MKx interface problem
  MKXSTATUS_TX_FAIL_HOST_RADIO_INTERFACE_PROBLEM= -780,
  /// TxEvent upload failed at the DSP
  MKXSTATUS_TX_EVENT_UPLOAD_FAIL_DSP            = -800,
  /// Ant1 I2C Temperature sensor read failure
  MKXSTATUS_I2C_TEMP_ANT1_FAILURE               = -810,
  /// Ant2 I2C Temperature sensor read failure
  MKXSTATUS_I2C_TEMP_ANT2_FAILURE               = -811,
  /// Ant1 ANALOG Temperature sensor read failure (SAF5400 Only)
  MKXSTATUS_ANALOG_TEMP_ANT1_FAILURE            = -812,
  /// Ant2 ANALOG Temperature sensor read failure (SAF5400 Only)
  MKXSTATUS_ANALOG_TEMP_ANT2_FAILURE            = -813,
  /// SAF5400 Internal Temperature sensor read failure (SAF5400 Only - Unused)
  MKXSTATUS_INTERNAL_TEMP_FAILURE               = -814,
  // Errors associated with Reception
  /// Overflow of packets at the RxMAC on the DSP
  MKXSTATUS_RX_MAC_BUFFER_OVERFLOW_DSP          = -832,
  /// Errors associated with Security
  /// Security message failed due to security accelerator not being present
  MKXSTATUS_SECURITY_ACCELERATOR_NOT_PRESENT    = -1024,
  /// Security message failed due to security FIFO being full
  MKXSTATUS_SECURITY_FIFO_FULL                  = -1025,
  /// Security message failed due to internal corruption
  MKXSTATUS_SECURITY_INTERNAL_ERROR             = -1026,
  /// Security message failed due to incoming message length too short
  MKXSTATUS_SECURITY_MSG_TOO_SHORT              = -1027,
  /// Invalid MKxGPIO Command
  MKXSTATUS_GPIO_INVALID_CMD                    = -1100,
  /// GPIO message failed due to FIFO being full
  MKXSTATUS_GPIO_FIFO_FULL                      = -1101,
  /// Received MKXIF Debug message with unexpected or invalid type
  MKXSTATUS_INVALID_DEBUGMSG_TYPE               = -1102,
  // Reserved
  MKXSTATUS_RESERVED                            = 0xC0DA
} eMKxStatus;
/// @copydoc eMKxStatus
typedef int tMKxStatus;

/// SAF5x00 error codes (additional message return codes)
/// These error codes correspond to a fault being detected on the SAF5x00 or
/// within the host LLC kernel module (grouped in the 2nd portion)
/// They are used as the return code for an MKXIF_ERROR message but can also
/// be used in tMKxStatus.
/// Primarily applicable for the function safety variants of SAF5300/SAF5400
typedef enum SAFErrorCode
{
  /// No error
  SAF_SUCCESS = 0,
  /// Received MKXIF message with unexpected or invalid type
  SAF_ERROR_INVALID_MKXIF_TYPE                      = -10000,
  /// Upload message type or length was corrupted
  SAF_ERROR_HOST_UPLOAD_MSG_CORRUPTED               = -10001,
  /// DSP fault asserted without an error code
  SAF_ERROR_DSP_UNKNOWN                             = -10002,
  /// Test fault condition reported by DSP, commanded by host message
  SAF_ERROR_DSP_FAULT_TEST                          = -10003,
  /// Test fault condition reported by ARM, commanded by host message
  SAF_ERROR_ARM_FAULT_TEST                          = -10004,
  /// Attempted to access a radio that does not exist in the system
  SAF_ERROR_RADIOB_UNSUPPORTED                      = -10005,
  /// Internal DSP to ARM Interrupt failure (DSP side)
  SAF_ERROR_DSP_TESTFAULT_FAILED                    = -10006,
  /// Internal DSP to ARM Interrupt failure (ARM side)
  SAF_ERROR_ARM_TESTFAULT_FAILED                    = -10007,
  /// Exception occurred on the DSP
  SAF_ERROR_DSP_EXCEPTION                           = -10008,
  /// Timeout (1s) waiting for DSP to be available to process RadioConfig msg
  SAF_ERROR_RADIOCONFIG_TIMEOUT                     = -10009,
  /// Error reading the one-time programmable (OTP) data
  SAF_ERROR_OTP_FAILURE                             = -10010,
  /// Attempted to retire a frame with queue index out of bounds
  SAF_ERROR_TXQUEUE_INDEX_OUT_OF_BOUNDS             = -10100,
  /// Attempted to retire a frame with a null QED
  SAF_ERROR_TXQUEUE_NULL_QED                        = -10101,
  /// Attempted to retire a frame with a null queue pointer
  SAF_ERROR_TXQUEUE_NULL_QUEUEPTR                   = -10102,
  /// Attempted to retire a frame with a null TxPkt pointer
  SAF_ERROR_TXQUEUE_NULL_TXPKT                      = -10103,
  /// Attempted to flush txqueue but locked up
  SAF_ERROR_TXQUEUE_FLUSH_WATCHDOG                  = -10104,
  /// Attempted to fail frame exchange on an inactive queue number
  SAF_ERROR_TXQUEUE_INACTIVE_QUEUENUM_FAILFEX       = -10105,
  /// UPL DMA lockup error where write pointer is not updated during tx
  SAF_ERROR_TX_UPL_DMA_WRPTR_LOCKUP                 = -10200,
  /// ARM received invalid ARMCmd type from the DSP
  SAF_ERROR_INVALID_ARM_CMD                         = -10300,
  /// DSP received an invalid command from the ARM
  SAF_ERROR_INVALID_DSP_CMD                         = -10301,
  /// Read or Write request when EEPROM was not detected on boot
  SAF_ERROR_EEPROM_NOT_PRESENT                      = -10400,
  /// Importing of calibration data failed due to EEPROM not being programmed
  SAF_ERROR_EEPROM_NOT_PROGRAMMED                   = -10401,
  /// EEPROM sleep command timed out indicating internal ARM timer has stopped
  SAF_ERROR_EEPROM_SLEEP_TIMEOUT                    = -10402,
  /// EEPROM read timeout event from I2C driver
  SAF_ERROR_EEPROM_READ_TIMEOUT                     = -10403,
  /// EEPROM read failed event from I2C driver
  SAF_ERROR_EEPROM_READ_FAILED                      = -10404,
  /// EEPROM read incomplete where not all requested bytes were read
  SAF_ERROR_EEPROM_READ_INCOMPLETE                  = -10405,
  /// EEPROM read overflow where more bytes than requested were read
  SAF_ERROR_EEPROM_OVERREAD                         = -10406,
  /// EEPROM I2C driver failed to set device address for read
  SAF_ERROR_EEPROM_READ_SET_DEVICE_ADDR_FAILED      = -10407,
  /// EEPROM I2C write failed to set address for upcoming read
  SAF_ERROR_EEPROM_READ_SET_ADDR_FAILED             = -10408,
  /// EEPROM write timeout event from I2C driver
  SAF_ERROR_EEPROM_WRITE_TIMEOUT                    = -10409,
  /// EEPROM write failed event from I2C driver
  SAF_ERROR_EEPROM_WRITE_FAILED                     = -10410,
  /// EEPROM write incomplete where not all requested bytes were written
  SAF_ERROR_EEPROM_WRITE_INCOMPLETE                 = -10411,
  /// EEPROM overflow where more bytes were written than requested
  SAF_ERROR_EEPROM_OVERWRITE                        = -10412,
  /// EEPROM I2C driver failed to set device address for write
  SAF_ERROR_EEPROM_WRITE_SET_DEVICE_ADDR_FAILED     = -10413,
  /// Bank requested is out of range (Range 0 to 3)
  SAF_ERROR_EEPROM_INVALID_BANK                     = -10414,
  /// Magic number in EEPROM is incorrect for import
  SAF_ERROR_EEPROM_INVALID_MAGIC                    = -10415,
  /// Version number in EEPROM is incorrect for import
  SAF_ERROR_EEPROM_INVALID_VERSION                  = -10416,
  /// Calculated CRC of EEPROM data did not match for import
  SAF_ERROR_EEPROM_INVALID_CRC                      = -10417,
  /// Write to bank 1 attempted but bank locked as magic number has been set
  SAF_ERROR_EEPROM_BANK_LOCKED                      = -10418,
  /// Memory access request is outside of valid range
  SAF_ERROR_INVALID_MEMORY_RANGE                    = -10500,
  /// Capture timed out
  SAF_ERROR_CAPTURE_TIMEOUT                         = -10600,
  /// Invalid TXPHY Register (Out of range)
  SAF_ERROR_INVALID_TXPHY_REGISTER                  = -10700,
  /// Invalid RXPHY Register (Out of range)
  SAF_ERROR_INVALID_RXPHY_REGISTER                  = -10701,
  /// Invalid CALIB Register (Out of range)
  SAF_ERROR_INVALID_CALIB_REGISTER                  = -10702,
  /// Invalid ARM Register (Out of range)
  SAF_ERROR_INVALID_ARM_REGISTER                    = -10703,
  /// Invalid RFE Register (Out of range)
  SAF_ERROR_INVALID_RFE_REGISTER                    = -10704,
  /// Invalid EEPROM0 Register (Out of range)
  SAF_ERROR_INVALID_EEPROM0_REGISTER                = -10705,
  /// Invalid EEPROM1 Register (Out of range)
  SAF_ERROR_INVALID_EEPROM1_REGISTER                = -10706,
  /// Invalid EEPROM2 Register (Out of range)
  SAF_ERROR_INVALID_EEPROM2_REGISTER                = -10707,
  /// Invalid Bank Read (Out of range)
  SAF_ERROR_INVALID_BANK_READ                       = -10708,
  /// Invalid Bank Write (Out of range)
  SAF_ERROR_INVALID_BANK_WRITE                      = -10709,
  /// Invalid MKxGPIO Command at the DSP
  SAF_ERROR_GPIO_INVALID_CMD                        = -10800,
  /// GPIO Internal Failure
  SAF_ERROR_GPIO_INTERNAL_ERROR                     = -10801,
  /// Received ARM Log command with invalid type
  SAF_ERROR_INVALID_ARMLOG_TYPE                     = -10900,
  /// Received DSP Log command with invalid type
  SAF_ERROR_INVALID_DSPLOG_TYPE                     = -10901,
  /// Internal ARM Log error due to an internal corruption
  SAF_ERROR_ARMLOG_INTERNAL_ERROR                   = -10902,
  /// C2XSec module received a message that is too short to even contain a USN
  SAF_ERROR_C2XSEC_MSG_TOO_SHORT_NO_USN             = -11000,
  /// C2XSec module received a command that is too short in length
  SAF_ERROR_C2XSEC_CMD_TOO_SHORT                    = -11001,
  /// C2XSec module received a message containing an unsupported instruction
  SAF_ERROR_C2XSEC_INS_NOT_SUPPORTED                = -11002,
  /// C2XSec module received an invalid curve ID
  SAF_ERROR_C2XSEC_CURVEID_INVALID                  = -11003,
  /// C2XSec module received a command whose length does not match its curve ID
  SAF_ERROR_C2XSEC_SIZE_MISMATCH_FOR_CURVEID        = -11004,
  /// C2XSec module received a reconstruct ECC public key command with wrong LC
  SAF_ERROR_C2XSEC_REPK_WRONG_LC                    = -11005,
  /// C2XSec module received a reconstruct ECC public key command with wrong
  /// length
  SAF_ERROR_C2XSEC_REPK_WRONG_LENGTH                = -11006,
  /// C2XSec module received a decompress public key command with wrong LC
  SAF_ERROR_C2XSEC_DPK_WRONG_LC                     = -11007,
  /// C2XSec module received a decompress public key command with wrong length
  SAF_ERROR_C2XSEC_DPK_WRONG_LENGTH                 = -11008,
  /// C2XSec module received a verify signature of hash command with wrong LC
  SAF_ERROR_C2XSEC_VSOH_WRONG_LC                    = -11009,
  /// C2XSec module received a verify signature of hash command with wrong
  /// length
  SAF_ERROR_C2XSEC_VSOH_WRONG_LENGTH                = -11010,
  /// C2XSec module received a decompress public key and verify signature of
  /// hash command with wrong LC
  SAF_ERROR_C2XSEC_DPK_VSOH_WRONG_LC                = -11011,
  /// C2XSec module received a decompress public key and verify signature of
  /// hash command with wrong length
  SAF_ERROR_C2XSEC_DPK_VSOH_WRONG_LENGTH            = -11012,
  /// ECDSA accelerator timeout during verify signature of hash operation
  /// for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_VSOH_TIMEOUT             = -11013,
  /// ECDSA accelerator timeout during decompress public key and verify
  /// signature of hash operation for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_DPK_VSOH_TIMEOUT         = -11014,
  /// ECDSA accelerator timeout during decompress public key operation
  /// for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_DPK_TIMEOUT              = -11015,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_REPK_TIMEOUT             = -11016,
  /// ECDSA accelerator timeout during verify signature of hash operation
  /// for BP256R1 curve ID
  SAF_ERROR_C2XSEC_BP256R1_VSOH_TIMEOUT             = -11017,
  /// ECDSA accelerator timeout during decompress public key and verify
  /// signature of hash operation for BP256R1 curve ID
  SAF_ERROR_C2XSEC_BP256R1_DPK_VSOH_TIMEOUT         = -11018,
  /// ECDSA accelerator timeout during decompress public key operation
  /// for BP256R1 curve ID
  SAF_ERROR_C2XSEC_BP256R1_DPK_TIMEOUT              = -11019,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for BP256R1 curve ID
  SAF_ERROR_C2XSEC_BP256R1_REPK_TIMEOUT             = -11020,
  /// ECDSA accelerator timeout during verify signature of hash operation
  /// for BP384R1 curve ID
  SAF_ERROR_C2XSEC_BP384R1_VSOH_TIMEOUT             = -11021,
  /// ECDSA accelerator timeout during decompress public key and verify
  /// signature of hash operation for BP384R1 curve ID
  SAF_ERROR_C2XSEC_BP384R1_DPK_VSOH_TIMEOUT         = -11022,
  /// ECDSA accelerator timeout during decompress public key operation
  /// for BP384R1 curve ID
  SAF_ERROR_C2XSEC_BP384R1_DPK_TIMEOUT              = -11023,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for BP384R1 curve ID
  SAF_ERROR_C2XSEC_BP384R1_REPK_TIMEOUT             = -11024,
  /// ECDSA accelerator timeout during verify signature of hash (fail) self
  /// test operation for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_VSOHF_TIMEOUT   = -11025,
  /// ECDSA accelerator verify signature of hash (fail) self test result
  /// mismatch for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_VSOHF_MISMATCH  = -11026,
  /// ECDSA accelerator timeout during verify signature of hash (pass) self
  /// test operation for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_VSOHP_TIMEOUT   = -11027,
  /// ECDSA accelerator verify signature of hash (pass) self test result
  /// mismatch for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_VSOHP_MISMATCH  = -11028,
  /// ECDSA accelerator timeout during decompress public key self test operation
  /// for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_DPK_TIMEOUT     = -11029,
  /// ECDSA accelerator decompress public key self test result mismatch
  /// for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_DPK_MISMATCH    = -11030,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_REPK_TIMEOUT    = -11031,
  /// ECDSA accelerator reconstruct ECC public key self test result mismatch
  /// for NIST256 curve ID
  SAF_ERROR_C2XSEC_NIST256_SELFTEST_REPK_MISMATCH   = -11032,
  /// C2XSec module detected internal memory corruption
  SAF_ERROR_C2XSEC_MEMORY_CORRUPTION_1              = -11033,
  /// C2XSec module detected internal memory corruption
  SAF_ERROR_C2XSEC_MEMORY_CORRUPTION_2              = -11034,
  /// C2XSec module detected internal memory corruption
  SAF_ERROR_C2XSEC_MEMORY_CORRUPTION_3              = -11035,
  /// C2XSec module detected internal memory corruption
  SAF_ERROR_C2XSEC_MEMORY_CORRUPTION_4              = -11036,
  /// Too many invalid 1PPS events
  SAF_ERROR_INVALID_1PPS_EVENT                      = -11100,
  /// Received invalid API Version length
  SAF_ERROR_INVALID_APIVERSION_LENGTH               = -11200,
  /// Received invalid Tx Packet length
  SAF_ERROR_INVALID_TXPACKET_LENGTH                 = -11201,
  /// Radio config message length invalid
  SAF_ERROR_INVALID_RADIOCONFIG_LENGTH              = -11202,
  /// Received invalid Flush Queue length
  SAF_ERROR_INVALID_FLUSHQ_LENGTH                   = -11203,
  /// Invalid input parameter value for Cmd of tMKxSetTSF
  SAF_ERROR_INVALID_SET_TSF_LENGTH                  = -11204,
  /// Received invalid GetTSF length
  SAF_ERROR_INVALID_GET_TSF_LENGTH                  = -11205,
  /// Debug message length invalid
  SAF_ERROR_INVALID_DEBUGMSG_LENGTH                 = -11206,
  /// Received Calibration command with invalid length
  SAF_ERROR_INVALID_CALIBRATION_LENGTH              = -11207,
  /// Received Set Temperature command with invalid length
  SAF_ERROR_INVALID_TEMP_LENGTH                     = -11208,
  /// Received AuxADC Configuration command with invalid length
  SAF_ERROR_INVALID_AUXADCCFG_LENGTH                = -11209,
  /// Received LOG command with invalid length
  SAF_ERROR_INVALID_LOG_LENGTH                      = -11210,
  /// Received GPIO command with invalid length
  SAF_ERROR_INVALID_GPIO_LENGTH                     = -11211,
  /// Received Reset command with invalid length
  SAF_ERROR_INVALID_RESET_LENGTH                    = -11212,
  /// Received Fault command with invalid length
  SAF_ERROR_INVALID_FAULT_LENGTH                    = -11213,
  /// SDIO interface detected an SDIO data transfer error
  SAF_ERROR_SDIO_ERROR_CALLBACK                     = -11300,
  /// Could not write to SDIO interface
  SAF_ERROR_SDIO_WRITE_FAILED                       = -11301,
  /// SDIO interface upload callback watchdog triggered
  SAF_ERROR_SDIO_UPLOAD_TIMEOUT                     = -11302,
  /// SDIO upload queue out of sync with upload request
  SAF_ERROR_SDIO_QUEUE_SYNC_FAILURE                 = -11303,
  /// Radio config received at DSP with invalid radio mode
  SAF_ERROR_DSP_INVALID_RADIO_MODE                  = -11400,
  /// Received invalid SetTSF command at DSP
  SAF_ERROR_DSP_SET_TSF_CMD_INVALID                 = -11401,
  /// DSP Failed to boot
  SAF_ERROR_DSP_INIT_WATCHDOG                       = -11402,
  /// DSP declared that ARM failed to initialise the Rx packet FIFO
  SAF_ERROR_DSP_RXMAC_INIT_WATCHDOG                 = -11403,
  /// Ethernet configuration failed
  SAF_ERROR_ETH_CONFIG_FAILED                       = -11500,
  /// Ethernet driver initialisation failed
  SAF_ERROR_ETH_DRV_INIT_FAILED                     = -11501,
  /// Ethernet driver configuration failed
  SAF_ERROR_ETH_DRV_CONFIG_FAILED                   = -11502,
  /// Ethernet ARP initialisation failed
  SAF_ERROR_ETH_ARP_INIT_FAILED                     = -11503,
  /// Ethernet ARP Resolve failed
  SAF_ERROR_ETH_ARP_RESOLVE_FAILED                  = -11504,
  /// Ethernet socket failed to initialise
  SAF_ERROR_ETH_SOCKET_INIT_FAILED                  = -11505,
  /// Ethernet failed to open the Tx socket to the host
  SAF_ERROR_ETH_INVALID_TX_SOCKET                   = -11506,
  /// Ethernet failed to open the Rx socket to the host
  SAF_ERROR_ETH_INVALID_RX_SOCKET                   = -11507,
  /// Ethernet initial UDP send failed
  SAF_ERROR_ETH_INITIAL_SEND_FAILED                 = -11508,
  /// Ethernet UDP send failed
  SAF_ERROR_ETH_UDP_SEND_FAILED                     = -11509,
  /// Ethernet Upload Callback Timeout
  SAF_ERROR_ETH_UPLOAD_TIMEOUT                      = -11510,
  /// Core Self Test range invalid
  SAF_ERROR_CST_RANGE_INVALID                       = -11600,
  /// Core Self Test failed
  SAF_ERROR_CST_TEST_FAILED                         = -11601,
  /// DMA channel acquisiton for SPI driver failed
  SAF_ERROR_SPI_DMA_ACQ_FAILED                      = -11700,
  /// SPI driver configuration failed
  SAF_ERROR_SPI_CONFIG_FAILED                       = -11701,
  /// Initial SPI read/write failed
  SAF_ERROR_SPI_INIT_RW_FAILED                      = -11702,
  /// SPI Data available timeout.  Host not responded after 100ms
  SAF_ERROR_SPI_DAV_TIMEOUT                         = -11703,
  /// SPI Hardware Error Callback
  SAF_ERROR_SPI_ERROR_CALLBACK                      = -11704,
  /// TxWMAC DMA channel acquisition failed
  SAF_ERROR_TXWMAC_DMA_ACQ_FAILED                   = -11800,
  /// TxWMAC acquired DMA channel configuration failed
  SAF_ERROR_TXWMAC_DMA_SET_CHAN_CONFIG_FAILED       = -11801,
  /// Setting TxWMAC DMA complete callback listener failed
  SAF_ERROR_TXWMAC_DMA_SET_LISTENER_FAILED          = -11802,
  /// TxWMAC DMA channel enabling failed
  SAF_ERROR_TXWMAC_DMA_CHAN_ENABLED_FAILED          = -11803,
  /// TxWMAC DMA1 callback timeout (period = 100ms)
  SAF_ERROR_TXWMAC_DMA1_TIMEOUT                     = -11804,
  /// TxWMAC DMA2 callback timeout (period = 100ms)
  SAF_ERROR_TXWMAC_DMA2_TIMEOUT                     = -11805,
  /// TxWMAC DMA1 Invalid Callback Event
  SAF_ERROR_TXWMAC_DMA1_INVALID_EVENT               = -11806,
  /// TxWMAC DMA2 Invalid Callback Event
  SAF_ERROR_TXWMAC_DMA2_INVALID_EVENT               = -11807,
  /// DSP to ARM message send blocked (i.e. failed)
  SAF_ERROR_DSP_MSG_SEND_BLOCKED                    = -11900,
  /// ARM to DSP command send blocked
  SAF_ERROR_DSP_CMD_SEND_BLOCKED                    = -11901,
  /// TxMAC TxPacket parameters invalid
  SAF_ERROR_TXMAC_TXPACKET_MALFORMED                = -12000,
  /// TxMAC TxPacket length parameter is too long
  SAF_ERROR_TXMAC_TXPACKET_LENGTH_TOO_LONG          = -12001,
  /// TxMAC TxPacket Management frame length parameter is too long
  SAF_ERROR_TXMAC_TXPACKET_MGMT_LENGTH_TOO_LONG     = -12002,
  /// TxPHY TxPacket internal pointer invalid
  SAF_ERROR_TXPHY_TXPACKET_PTR_INVALID              = -12003,
  /// TxPHY TxPacket parameters invalid
  SAF_ERROR_TXPHY_TXPACKET_MALFORMED                = -12004,
  /// Temperature I2C Ant 1 Sensor Failure
  SAF_ERROR_TEMP_I2C_ANT1_FAILED                    = -12100,
  /// Temperature I2C Ant 2 Sensor Failure
  SAF_ERROR_TEMP_I2C_ANT2_FAILED                    = -12101,
  /// Temperature Analog Ant 1 Sensor Failure
  SAF_ERROR_TEMP_ANALOG_ANT1_FAILED                 = -12102,
  /// Temperature Analog Ant 2 Sensor Failure
  SAF_ERROR_TEMP_ANALOG_ANT2_FAILED                 = -12103,
  /// Temperature Power Correction outside limits Ant1
  SAF_ERROR_TEMP_POWERCAL_ANT1_INVALID              = -12104,
  /// Temperature Power Correction outside limits Ant2
  SAF_ERROR_TEMP_POWERCAL_ANT2_INVALID              = -12105,
  /// TxPHY SF Encode failure
  SAF_ERROR_TX_SFENC_FAILED                         = -12200,
  /// TxPHY Payload Encode failure
  SAF_ERROR_TX_PAYLOADENC_FAILED                    = -12201,
  /// Tx Power Correction outside limits Ant1
  SAF_ERROR_TX_POWERCAL_ANT1_INVALID                = -12202,
  /// Tx Power Correction outside limits Ant2
  SAF_ERROR_TX_POWERCAL_ANT2_INVALID                = -12203,
  /// Tx Cyclic Shift Offset Out Of Bounds
  SAF_ERROR_TX_CYCLICSHIFT_INVALID                  = -12204,
  /// Rx Orbit RxSF failure
  SAF_ERROR_RX_RXSF_FAILED                          = -12300,
  /// Rx Orbit RxReDecode failure
  SAF_ERROR_RX_RXREDECODE_FAILED                    = -12301,
  /// Rx AGC Unfreeze failure
  SAF_ERROR_RX_AGCUNFREEZE_TIMEOUT                  = -12302,
  /// Rx Coarse Timing failure
  SAF_ERROR_RX_COARSETIMING_FAILURE                 = -12303,
  /// Rx Invalid Antenna during configuration
  SAF_ERROR_RX_START_INVALID_ANT                    = -12304,
  /// Tx-Rx RF Loopback signal field decode failure (doesn't match expected)
  SAF_ERROR_TXRXLOOPBACK_DECODE_FAILED              = -12400,
  /// Tx-RX RF Loopback Start_RxReDecode failure
  SAF_ERROR_TXRXLOOPBACK_RXREDECODE_FAILED          = -12401,
  /// Tx-RX RF Loopback RxSignalField failure
  SAF_ERROR_TXRXLOOPBACK_RXSF_FAILED                = -12402,
  /// Tx-RX RF Loopback Coarse Timing failure
  SAF_ERROR_TXRXLOOPBACK_COARSETIME_FAILED          = -12403,
  /// Calibration of the TRX failure
  SAF_ERROR_RFE_TIMEOUT_CALTRX                      = -12500,
  /// Calibration NewRadioConfig failure
  SAF_ERROR_RFE_TIMEOUT_NEWRADIOCONFIG              = -12501,
  /// ConfigManager Init failure
  SAF_ERROR_RFE_TIMEOUT_CONFIGINIT                  = -12502,
  /// Calibration GPIO update failure
  SAF_ERROR_RFE_TIMEOUT_GPIOPINUPDATE               = -12503,
  /// Register Write RFE falure
  SAF_ERROR_RFE_TIMEOUT_REGISTERWRITE               = -12504,
  /// Overflow of the upload to the LLC of MKXIF_APIVERSION message
  SAF_ERROR_LLC_UPLOAD_OVERFLOW_APIVERSION          = -12600,
  /// Overflow of the upload to the LLC of MKXIF_TXPACKET message
  SAF_ERROR_LLC_UPLOAD_OVERFLOW_TXPACKET            = -12601,
  /// Overflow of the upload to the LLC of MKXIF_GPIO buffer full message
  SAF_ERROR_LLC_UPLOAD_OVERFLOW_GPIO                = -12602,
  /// Overflow of the upload to the LLC of MKXIF_LOOPBACK message
  SAF_ERROR_LLC_UPLOAD_OVERFLOW_LOOPBACK            = -12603,
  /// Overflow of the upload to the LLC of MKXIF_FAULT message
  SAF_ERROR_LLC_UPLOAD_OVERFLOW_FAULT               = -12604,
  /// Overflow of the upload to the LLC of MKXIF_DEBUG Compensator message
  SAF_ERROR_LLC_UPLOAD_OVERFLOW_COMPENSATOR         = -12605,
  /// Overflow of the upload to the LLC of MKXIF_CALIBRATION message
  SAF_ERROR_LLC_UPLOAD_OVERFLOW_CALIBRATION         = -12606,
  /// Compensator Processing Timeout
  SAF_ERROR_COMPENSATOR_TIMEOUT                     = -12700,
  /// Compensator CRC Failure
  SAF_ERROR_COMPENSATOR_CRC_FAILURE                 = -12701,
  /// TX Power Correction outside limits Ant1
  SAF_ERROR_COMPENSATOR_POWERCAL_ANT1_INVALID       = -12702,
  /// TX Power Correction outside limits Ant2
  SAF_ERROR_COMPENSATOR_POWERCAL_ANT2_INVALID       = -12703,
  /// No data is being received from the Compensator
  SAF_ERROR_COMPENSATOR_NO_DATA_RECEIVED            = -12704,
  /// TimeSync Internal Failure
  SAF_ERROR_TIMESYNC_INTERNAL_FAILURE               = -12800,
  /// RxWMAC Received Corrupted Packet
  SAF_ERROR_RXWMAC_CORRUPT_PACKET                   = -12900,
  /// ECC Double bit overflow error ARM IMEM
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_OVERFLOW_ARMIMEM     = -13000,
  /// ECC Double bit error ARM IMEM
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_ARMIMEM              = -13001,
  /// ECC Double bit overflow error ARM DMEM
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_OVERFLOW_ARMDMEM     = -13002,
  /// ECC Double bit error ARM DMEM
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_ARMDMEM              = -13003,
  /// ECC Double bit overflow error ECDSA
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_OVERFLOW_ECDSA       = -13004,
  /// ECC Double bit error error ECDSA
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_ECDSA                = -13005,
  /// Parity overflow error SYSMEM
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_SYSMEM          = -13006,
  /// Parity error SYSMEM
  SAF_ERROR_FSM_MEM_PARITY_SYSMEM                   = -13007,
  /// Parity overflow error EMACTX
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_EMACTX          = -13008,
  /// Parity error EMACTX
  SAF_ERROR_FSM_MEM_PARITY_EMACTX                   = -13009,
  /// Parity overflow error EMACRX
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_EMACRX          = -13010,
  /// Parity error EMACRX
  SAF_ERROR_FSM_MEM_PARITY_EMACRX                   = -13011,
  /// Parity overflow error SDIOSRAM
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_SDIOSRAM        = -13012,
  /// Parity error SDIOSRAM
  SAF_ERROR_FSM_MEM_PARITY_SDIOSRAM                 = -13013,
  /// Parity overflow error SDIOCISSRAM
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_SDIOCISSRAM     = -13014,
  /// Parity error SDIOCISSRAM
  SAF_ERROR_FSM_MEM_PARITY_SDIOCISSRAM              = -13015,
  /// Parity overflow error ECDSA CRYPTO0
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_CRYPTO0         = -13016,
  /// Parity error ECDSA CRYPTO0
  SAF_ERROR_FSM_MEM_PARITY_CRYPTO0                  = -13017,
  /// Parity overflow error ECDSA CRYPTO1
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_CRYPTO1         = -13018,
  /// Parity error ECDSA CRYPTO1
  SAF_ERROR_FSM_MEM_PARITY_CRYPTO1                  = -13019,
  /// ECC Double bit overflow error BBEIRAM0
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_OVERFLOW_BBEIRAM0    = -13020,
  /// ECC Double bit error BBEIRAM0
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_BBEIRAM0             = -13021,
  /// ECC Double bit overflow error BBEIRAM1
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_OVERFLOW_BBEIRAM1    = -13022,
  /// ECC Double bit error BBEIRAM1
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_BBEIRAM1             = -13023,
  /// Parity overflow error BBEDRAM00
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_BBEDRAM00       = -13024,
  /// Parity error BBEDRAM00
  SAF_ERROR_FSM_MEM_PARITY_BBEDRAM00                = -13025,
  /// Parity overflow error BBEDRAM01
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_BBEDRAM01       = -13026,
  /// Parity error BBEDRAM01
  SAF_ERROR_FSM_MEM_PARITY_BBEDRAM01                = -13027,
  /// Parity overflow error BBEDRAM02
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_BBEDRAM02       = -13028,
  /// Parity error BBEDRAM02
  SAF_ERROR_FSM_MEM_PARITY_BBEDRAM02                = -13029,
  /// Parity overflow error BBEDRAM03
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_BBEDRAM03       = -13030,
  /// Parity error BBEDRAM03
  SAF_ERROR_FSM_MEM_PARITY_BBEDRAM03                = -13031,
  /// Parity overflow error BBEDRAM10
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_BBEDRAM10       = -13032,
  /// Parity error BBEDRAM10
  SAF_ERROR_FSM_MEM_PARITY_BBEDRAM10                = -13033,
  /// Parity overflow error BBEDRAM11
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_BBEDRAM11       = -13034,
  /// Parity error BBEDRAM11
  SAF_ERROR_FSM_MEM_PARITY_BBEDRAM11                = -13035,
  /// Parity overflow error ORBITSP0
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_ORBITSP0        = -13036,
  /// Parity error ORBITSP0
  SAF_ERROR_FSM_MEM_PARITY_ORBITSP0                 = -13037,
  /// Parity overflow error ORBITSP1
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_ORBITSP1        = -13038,
  /// Parity error ORBITSP1
  SAF_ERROR_FSM_MEM_PARITY_ORBITSP1                 = -13039,
  /// Parity overflow error ORBITSP2
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_ORBITSP2        = -13040,
  /// Parity error ORBITSP2
  SAF_ERROR_FSM_MEM_PARITY_ORBITSP2                 = -13041,
  /// Parity overflow error ORBITSP3
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_ORBITSP3        = -13042,
  /// Parity error ORBITSP3
  SAF_ERROR_FSM_MEM_PARITY_ORBITSP3                 = -13043,
  /// Parity overflow error ORBITDP0
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_ORBITDP0        = -13044,
  /// Parity error ORBITDP0
  SAF_ERROR_FSM_MEM_PARITY_ORBITDP0                 = -13045,
  /// Parity overflow error ORBITDP1
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_ORBITDP1        = -13046,
  /// Parity error ORBITDP1
  SAF_ERROR_FSM_MEM_PARITY_ORBITDP1                 = -13047,
  /// ECC Double bit overflow error X2
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_OVERFLOW_X2          = -13048,
  /// ECC Double bit error X2
  SAF_ERROR_FSM_MEM_ECC_DOUBLE_X2                   = -13049,
  /// Parity overflow error X2DMEM0
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_X2DMEM0         = -13050,
  /// Parity error X2DMEM0
  SAF_ERROR_FSM_MEM_PARITY_X2DMEM0                  = -13051,
  /// Parity overflow error X2DMEM1
  SAF_ERROR_FSM_MEM_PARITY_OVERFLOW_X2DMEM1         = -13052,
  /// Parity error X2DMEM1
  SAF_ERROR_FSM_MEM_PARITY_X2DMEM1                  = -13053,
  /// ECC single bit overflow error ARMIMEM
  SAF_ERROR_FSM_MEM_ECC_SINGLE_OVERFLOW_ARMIMEM     = -13070,
  /// ECC single bit error ARMIMEM
  SAF_ERROR_FSM_MEM_ECC_SINGLE_ARMIMEM              = -13071,
  /// ECC single bit overflow error ARMDMEM
  SAF_ERROR_FSM_MEM_ECC_SINGLE_OVERFLOW_ARMDMEM     = -13072,
  /// ECC single bit error ARMDMEM
  SAF_ERROR_FSM_MEM_ECC_SINGLE_ARMDMEM              = -13073,
  /// ECC single bit overflow error ECDSA
  SAF_ERROR_FSM_MEM_ECC_SINGLE_OVERFLOW_ECDSA       = -13074,
  /// ECC single bit error ECDSA
  SAF_ERROR_FSM_MEM_ECC_SINGLE_ECDSA                = -13075,
  /// ECC single bit overflow error BBEIRAM0
  SAF_ERROR_FSM_MEM_ECC_SINGLE_OVERFLOW_BBEIRAM0    = -13076,
  /// ECC single bit error BBEIRAM0
  SAF_ERROR_FSM_MEM_ECC_SINGLE_BBEIRAM0             = -13077,
  /// ECC single bit overflow error BBEIRAM1
  SAF_ERROR_FSM_MEM_ECC_SINGLE_OVERFLOW_BBEIRAM1    = -13078,
  /// ECC single bit error BBEIRAM1
  SAF_ERROR_FSM_MEM_ECC_SINGLE_BBEIRAM1             = -13079,
  /// ECC single bit overflow error X2
  SAF_ERROR_FSM_MEM_ECC_SINGLE_OVERFLOW_X2          = -13080,
  /// ECC single bit error X2
  SAF_ERROR_FSM_MEM_ECC_SINGLE_X2                   = -13081,
  /// BBE Write Response Error, Reserved address/Illegal write to BBE memory
  SAF_ERROR_FSM_MEM_DSP_ILLEGAL_WRITE               = -13088,
  /// ARMWDT Interrupt Error
  SAF_ERROR_FSM_ARM_WATCHDOG                        = -13089,
  /// MDMWDT Interrupt Error
  SAF_ERROR_FSM_DSP_WATCHDOG                        = -13090,
  /// RFEWDT Interrupt Error
  SAF_ERROR_FSM_X2_WATCHDOG                         = -13091,
  /// ARMPLL0 unlock Error (unused)
  SAF_ERROR_FSM_ARM_PLL0_UNLOCK                     = -13092,
  /// ARMPLL1 unlock Error (unused)
  SAF_ERROR_FSM_ARM_PLL1_UNLOCK                     = -13093,
  /// RFEPLL unlock Error (unused)
  SAF_ERROR_FSM_X2_PLL_UNLOCK                       = -13094,
  /// Core self-test failure Exception Test Svc
  SAF_ERROR_CST_EXCEPTION_TEST_SVC                  = -14000,
  /// Core self-test failure Exception Test Pendsv
  SAF_ERROR_CST_EXCEPTION_TEST_PENDSV               = -14001,
  /// Core self-test failure Exception Test Sys tick
  SAF_ERROR_CST_EXCEPTION_TEST_SYSTICK              = -14002,
  /// Core self-test failure Exception Hard Fault1
  SAF_ERROR_CST_EXCEPTION_HARD_FAULT1               = -14003,
  /// Core self-test failure Exception Hard Fault2
  SAF_ERROR_CST_EXCEPTION_HARD_FAULT2               = -14004,
  /// Core self-test failure Exception Usage Fault
  SAF_ERROR_CST_EXCEPTION_USAGE_FAULT               = -14005,
  /// Core self-test failure Exception Mem Fault
  SAF_ERROR_CST_EXCEPTION_MEM_FAULT                 = -14006,
  /// Core self-test failure Exception Bus Fault
  SAF_ERROR_CST_EXCEPTION_BUS_FAULT                 = -14007,
  /// Core self-test failure Exception Test Nmihf
  SAF_ERROR_CST_EXCEPTION_TEST_NMIHF                = -14008,
  /// Core self-test failure Exception Test Tail Chain
  SAF_ERROR_CST_EXCEPTION_TEST_TAILCHAIN            = -14009,
  /// Core self-test failure Exception Test Masking
  SAF_ERROR_CST_EXCEPTION_TEST_MASKING              = -14010,
  /// Core self-test failure Exception Test Handler Thread
  SAF_ERROR_CST_EXCEPTION_TEST_HANDLER              = -14011,
  /// Core self-test failure Regbank Test4
  SAF_ERROR_CST_REGBANK_TEST4                       = -14012,
  /// Core self-test failure ALU Test7
  SAF_ERROR_CST_ALU_TEST7                           = -14013,
  /// Core self-test failure Branch Test3
  SAF_ERROR_CST_BRANCH_TEST3                        = -14014,
  /// Core self-test failure Status Test3
  SAF_ERROR_CST_STATUS_TEST3                        = -14015,
  /// Core self-test failure Regbank Test6
  SAF_ERROR_CST_REGBANK_TEST6                       = -14016,
  /// Core self-test failure Fetch Test
  SAF_ERROR_CST_FETCH_TEST                          = -14017,
  /// Core self-test failure Load store Test6
  SAF_ERROR_CST_LOADSTORE_TEST6                     = -14018,
  /// Core self-test failure Load store Test1
  SAF_ERROR_CST_LOADSTORE_TEST1                     = -14019,
  /// Core self-test failure Load store Test2
  SAF_ERROR_CST_LOADSTORE_TEST2                     = -14020,
  /// Core self-test failure Load store Test3
  SAF_ERROR_CST_LOADSTORE_TEST3                     = -14021,
  /// Core self-test failure Load store Test4
  SAF_ERROR_CST_LOADSTORE_TEST4                     = -14022,
  /// Core self-test failure Load store Test5
  SAF_ERROR_CST_LOADSTORE_TEST5                     = -14023,
  /// Core self-test failure Regbank Test1
  SAF_ERROR_CST_REGBANK_TEST1                       = -14024,
  /// Core self-test failure Regbank Test2
  SAF_ERROR_CST_REGBANK_TEST2                       = -14025,
  /// Core self-test failure Regbank Test3
  SAF_ERROR_CST_REGBANK_TEST3                       = -14026,
  /// Core self-test failure Regbank Test5
  SAF_ERROR_CST_REGBANK_TEST5                       = -14027,
  /// Core self-test failure ALU Test1
  SAF_ERROR_CST_ALU_TEST1                           = -14028,
  /// Core self-test failure ALU Test2
  SAF_ERROR_CST_ALU_TEST2                           = -14029,
  /// Core self-test failure ALU Test3
  SAF_ERROR_CST_ALU_TEST3                           = -14030,
  /// Core self-test failure ALU Test4
  SAF_ERROR_CST_ALU_TEST4                           = -14031,
  /// Core self-test failure ALU Test5
  SAF_ERROR_CST_ALU_TEST5                           = -14032,
  /// Core self-test failure ALU Test6
  SAF_ERROR_CST_ALU_TEST6                           = -14033,
  /// Core self-test failure Branch Test1
  SAF_ERROR_CST_BRANCH_TEST1                        = -14034,
  /// Core self-test failure Status Test1
  SAF_ERROR_CST_STATUS_TEST1                        = -14035,
  /// Core self-test failure MAC Test1
  SAF_ERROR_CST_MAC_TEST1                           = -14036,
  /// Core self-test failure MAC Test2
  SAF_ERROR_CST_MAC_TEST2                           = -14037,
  /// Core self-test failure Status Test2
  SAF_ERROR_CST_STATUS_TEST2                        = -14038,
  /// Core self-test failure Branch Test2
  SAF_ERROR_CST_BRANCH_TEST2                        = -14039,
  /// Peripheral self-test outclk SAFEREF failure
  SAF_ERROR_PST_CGU_OUTCLK0_SAFEREF                 = -14100,
  /// Peripheral self-test outclk ARM failure
  SAF_ERROR_PST_CGU_OUTCLK1_ARM                     = -14101,
  /// Peripheral self-test outclk HSPI failure
  SAF_ERROR_PST_CGU_OUTCLK2_HSPI                    = -14102,
  /// Peripheral self-test outclk AES failure
  SAF_ERROR_PST_CGU_OUTCLK3_AES                     = -14103,
  /// Peripheral self-test outclk BA414EP failure
  SAF_ERROR_PST_CGU_OUTCLK4_BA414EP                 = -14104,
  /// Peripheral self-test outclk SYSAPB failure
  SAF_ERROR_PST_CGU_OUTCLK5_SYSAPB                  = -14105,
  /// Peripheral self-test outclk WDT failure
  SAF_ERROR_PST_CGU_OUTCLK6_WDT                     = -14106,
  /// Peripheral self-test outclk PERIAPB failure
  SAF_ERROR_PST_CGU_OUTCLK7_PERIAPB                 = -14107,
  /// Peripheral self-test outclk I2C failure
  SAF_ERROR_PST_CGU_OUTCLK8_I2C                     = -14108,
  /// Peripheral self-test outclk UART failure
  SAF_ERROR_PST_CGU_OUTCLK9_UART                    = -14109,
  /// Peripheral self-test outclk QSPI failure
  SAF_ERROR_PST_CGU_OUTCLK10_QSPI                   = -14110,
  /// Peripheral self-test outclk BBE16 failure
  SAF_ERROR_PST_CGU_OUTCLK11_BBE16                  = -14111,
  /// Peripheral self-test outclk TIMER failure
  SAF_ERROR_PST_CGU_OUTCLK12_TIMER                  = -14112,
  /// Peripheral self-test outclk RMII failure
  SAF_ERROR_PST_CGU_OUTCLK13_RMII                   = -14113,
  /// Peripheral self-test outclk RMIIRX failure
  SAF_ERROR_PST_CGU_OUTCLK14_RMIIRX                 = -14114,
  /// Peripheral self-test outclk RMIITX failure
  SAF_ERROR_PST_CGU_OUTCLK15_RGMIITX                = -14115,
  /// Peripheral self-test outclk REF CLK1 failure
  SAF_ERROR_PST_CGU_OUTCLK16_REFCLK1                = -14116,
  /// Peripheral self-test outclk REF CLK2 failure
  SAF_ERROR_PST_CGU_OUTCLK17_REFCLK2                = -14117,
  /// Peripheral self-test outclk WRCK failure
  SAF_ERROR_PST_CGU_OUTCLK18_WRCK                   = -14118,
  /// Peripheral self-test failure Bus interconnect AHB2APB SYS
  SAF_ERROR_PST_BUS_SYS                             = -14119,
  /// Peripheral self-test failure Bus interconnect AHB2VPBT ARM Timers
  SAF_ERROR_PST_BUS_ARM_TIMERS                      = -14120,
  /// Peripheral self-test failure Bus interconnect AHB2VPBT RFE Timer
  SAF_ERROR_PST_BUS_RFE_TIMER                       = -14121,
  /// Peripheral self-test failure Bus interconnect ORBIT State CRC
  SAF_ERROR_PST_BUS_ORBIT_STATE_CRC                 = -14122,
  /// Peripheral self-test failure Chip Infra RGU
  SAF_ERROR_PST_CHIP_INFRA_RGU                      = -14123,
  /// Peripheral self-test failure Chip Infra CREG
  SAF_ERROR_PST_CHIP_INFRA_CREG                     = -14124,
  /// Peripheral self-test failure Chip Infra SCU Bank 2
  SAF_ERROR_PST_CHIP_INFRA_SCU_BANK2                = -14125,
  /// Peripheral self-test failure Chip Infra SCU Bank 3
  SAF_ERROR_PST_CHIP_INFRA_SCU_BANK3                = -14126,
  /// Peripheral self-test failure Chip Infra ARM Timers
  SAF_ERROR_PST_CHIP_INFRA_ARM_TIMERS               = -14127,
  /// Peripheral self-test failure Chip Infra ARM Watchdog
  SAF_ERROR_PST_CHIP_INFRA_ARM_WDT                  = -14128,
  /// Peripheral self-test failure Chip Infra DSP Watchdog
  SAF_ERROR_PST_CHIP_INFRA_DSP_WDT                  = -14129,
  /// Peripheral self-test failure Peripheral Infra UART1
  SAF_ERROR_PST_PERIPH_INFRA_UART1                  = -14132,
  /// Peripheral self-test failure Peripheral Infra UART2
  SAF_ERROR_PST_PERIPH_INFRA_UART2                  = -14133,
  /// Peripheral self-test failure Peripheral Infra UART3
  SAF_ERROR_PST_PERIPH_INFRA_UART3                  = -14134,
  /// Peripheral self-test failure Peripheral Infra UART4
  SAF_ERROR_PST_PERIPH_INFRA_UART4                  = -14135,
  /// Peripheral self-test failure Peripheral Infra QSPI
  SAF_ERROR_PST_PERIPH_INFRA_QSPI                   = -14136,
  /// Peripheral self-test failure Peripheral Infra I2C
  SAF_ERROR_PST_PERIPH_INFRA_I2C                    = -14137,
  /// Peripheral self-test failure Peripheral Infra I2C Internal Regs
  SAF_ERROR_PST_PERIPH_INFRA_I2CINT                 = -14138,
  /// Peripheral self-test failure Peripheral Infra GPIO Toggle
  SAF_ERROR_PST_PERIPH_INFRA_GPIO_TOGGLE            = -14139,
  /// Peripheral self-test failure Peripheral Infra GPIO Loopback
  SAF_ERROR_PST_PERIPH_INFRA_GPIO_LOOPBACK          = -14140,
  /// Peripheral self-test failure DMA
  SAF_ERROR_PST_DMA                                 = -14141,
  /// Peripheral self-test failure ECDSA
  SAF_ERROR_PST_ECDSA                               = -14142,
  /// Peripheral self-test failure Verify OTP
  SAF_ERROR_PST_VERIFY_OTP                          = -14143,
  /// Peripheral self-test failure OTP Integrity NXP bank
  SAF_ERROR_PST_OTP_INTEGRITY_NXP                   = -14144,
  /// Peripheral self-test failure OTP Integrity Customer bank
  SAF_ERROR_PST_OTP_INTEGRITY_CUSTOMER              = -14145,
  /// PST clock test requested is out of range
  SAF_ERROR_PST_CGU_CLOCKS_OUTOFRANGE               = -14200,
  /// PST clocks test config is invalid (0/null)
  SAF_ERROR_PST_CGU_CLOCKS_INVALIDCONFIG            = -14201,
  /// PST Orbit failure for MCS0
  SAF_ERROR_PST_ORBIT_FAILURE_MCS0                  = -14300,
  /// PST Orbit failure for MCS1
  SAF_ERROR_PST_ORBIT_FAILURE_MCS1                  = -14301,
  /// PST Orbit failure for MCS2
  SAF_ERROR_PST_ORBIT_FAILURE_MCS2                  = -14302,
  /// PST Orbit failure for MCS3
  SAF_ERROR_PST_ORBIT_FAILURE_MCS3                  = -14303,
  /// PST Orbit failure for MCS4
  SAF_ERROR_PST_ORBIT_FAILURE_MCS4                  = -14304,
  /// PST Orbit failure for MCS5
  SAF_ERROR_PST_ORBIT_FAILURE_MCS5                  = -14305,
  /// PST Orbit failure for MCS6
  SAF_ERROR_PST_ORBIT_FAILURE_MCS6                  = -14306,
  /// PST Orbit failure for MCS7
  SAF_ERROR_PST_ORBIT_FAILURE_MCS7                  = -14307,
  // MBIST status errors
  /// Memory self-test was completed but test failed for some mem ring(s)
  SAF_ERROR_MBIST_COMPLETED_FAILED                  = -14400,
  /// Memory self-test was not completed (aborted), thus failed
  SAF_ERROR_MBIST_NOT_COMPLETED_FAILED              = -14401,
  // Boot status errors
  /// Boot status PBL to SBL booting failure
  SAF_ERROR_BOOT_STATUS_BOOT_FAILURE                = -14500,
  /// Boot status PBL to SBL Read over i/f failure
  SAF_ERROR_BOOT_STATUS_READ_FAILURE                = -14501,
  /// Boot status PBL to SBL phase Authentication failure
  SAF_ERROR_BOOT_STATUS_AUTH_FAILURE                = -14502,
  /// Boot status PBL to SBL phase ID verification failure
  SAF_ERROR_BOOT_STATUS_ID_VERF_FAILURE             = -14503,
  /// Boot status PBL to SBL phase BSH not found failure
  SAF_ERROR_BOOT_STATUS_BSH_NOT_FOUND               = -14504,
  /// Boot status PBL to SBL phase BSH ended unexpected failure
  SAF_ERROR_BOOT_STATUS_BSH_ENDED_FAILURE           = -14505,
  /// Boot status PBL to SBL phase invalid target address failure
  SAF_ERROR_BOOT_STATUS_INVALID_TARGET_ADDR         = -14506,
  /// Boot status PBL to SBL phase invalid boot command
  SAF_ERROR_BOOT_STATUS_INVALID_CMD                 = -14507,
  /// Boot status PBL to SBL phase invalid boot mode
  SAF_ERROR_BOOT_STATUS_INVALID_BOOT_MODE           = -14508,
  /// Boot status PBL to SBL phase flash invalid address
  SAF_ERROR_BOOT_STATUS_FLASH_INVALID_ADDR          = -14509,
  /// Boot status PBL to SBL phase decryption failure
  SAF_ERROR_BOOT_STATUS_DECRYPTION_FAILURE          = -14510,
  /// Boot status PBL to SBL phase security init failure
  SAF_ERROR_BOOT_STATUS_SECURITY_INIT_FAILURE       = -14511,
  /// Boot status PBL to SBL phase security OTP read failure
  SAF_ERROR_BOOT_STATUS_SECURITY_OTP_READ_FAILURE   = -14512,
  /// Boot status PBL to SBL phase security config mismatch failure
  SAF_ERROR_BOOT_STATUS_SECURITY_CONFIG_MISMATCH    = -14513,
  /// Boot status PBL to SBL phase CRC check failure
  SAF_ERROR_BOOT_STATUS_CRC_CHECK_FAILURE           = -14514,
  /// Boot status PBL to SBL phase chunk id verification failure
  SAF_ERROR_BOOT_STATUS_CHUNK_ID_VERF_FAILURE       = -14515,
  /// Boot status PBL to SBL phase image format mismatch failure
  SAF_ERROR_BOOT_STATUS_IMG_FORMAT_MISMATCH         = -14516,
  /// Boot status PBL to SBL phase public key verification failure
  SAF_ERROR_BOOT_STATUS_PUB_KEY_VERF_FAILURE        = -14517,
  /// Boot status PBL to SBL phase customer OTP not programmed failure
  SAF_ERROR_BOOT_STATUS_CUSTOMER_OTP_NOT_PROG       = -14518,
  /// Boot status PBL to SBL phase Flash init failure
  SAF_ERROR_BOOT_STATUS_FLASH_INIT_FAILURE          = -14519,
  /// Invalid input parameter value for RadioID of tMKxTxPacket
  SAF_ERROR_INVALIDINPUT_TXPKT_RADIOID              = -15000,
  /// Invalid input parameter value for ChannelID of tMKxTxPacket
  SAF_ERROR_INVALIDINPUT_TXPKT_CHANNELID            = -15001,
  /// Invalid input parameter value for TxAntenna of tMKxTxPacket
  SAF_ERROR_INVALIDINPUT_TXPKT_TXANT                = -15002,
  /// Invalid input parameter value for MCS of tMKxTxPacket
  SAF_ERROR_INVALIDINPUT_TXPKT_MCS                  = -15003,
  /// Invalid input parameter value for TxPower of tMKxTxPacket
  SAF_ERROR_INVALIDINPUT_TXPKT_TXPOWER              = -15004,
  /// Invalid input parameter value for TxFrameLength of tMKxTxPacket
  SAF_ERROR_INVALIDINPUT_TXPKT_TXFRAMELENGTH        = -15005,
  /// Invalid input parameter value for Cmd of tMKxSetTSF
  SAF_ERROR_INVALIDINPUT_SETTSF_CMD                 = -15100,
  /// Invalid input parameter value for UTC of tMKxSetTSF
  SAF_ERROR_INVALIDINPUT_SETTSF_UTC                 = -15101,
  /// Invalid input parameter value for TSF of tMKxSetTSF
  SAF_ERROR_INVALIDINPUT_SETTSF_TSF                 = -15102,
  /// Invalid input parameter value for Mode of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_MODE              = -15200,
  /// Invalid input parameter value for ChannelFreq of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_CHANNELFREQ       = -15201,
  /// Invalid input parameter value for Bandwidth of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_BW                = -15202,
  /// Invalid input parameter value for TxAntenna of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_TXANT             = -15203,
  /// Invalid input parameter value for RxAntenna of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_RXANT             = -15204,
  /// Invalid input parameter value for DefaultMCS of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_DEFAULTMCS        = -15205,
  /// Invalid input parameter value for DefaultTxPower of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_DEFAULTTXPOWER    = -15206,
  /// Invalid input parameter value for DualTxControl of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_DUALTXCTRL        = -15207,
  /// Invalid input parameter value for CSThreshold of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_CSTHRESH          = -15208,
  /// Invalid input parameter value for CBRThreshold of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_CBRTHRESH         = -15209,
  /// Invalid input parameter value for SlotTime of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_SLOTTIME          = -15210,
  /// Invalid input parameter value for DIFSTime of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_DIFSTIME          = -15211,
  /// Invalid input parameter value for SIFSTime of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_SIFSTIME          = -15212,
  /// Invalid input parameter value for EFISTime of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_EIFSTIME          = -15213,
  /// Invalid input parameter value for ShortRetryLimit of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_SHORTRETRY        = -15214,
  /// Invalid input parameter value for LongRetryLimit of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_LONGRETRY         = -15215,
  /// Invalid input parameter value for TxQueue.AIFS of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_AIFS              = -15216,
  /// Invalid input parameter value for TxQueue.CWMIN of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_CWMIN             = -15217,
  /// Invalid input parameter value for TxQueue.CWMAX of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_CWMAX             = -15218,
  /// Invalid input parameter value for TxQueue.TXOP of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_TXOP              = -15219,
  /// Invalid input parameter value for IntervalDuration of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_INTERVAL          = -15220,
  /// Invalid input parameter value for GuardDuration of tMKxRadioConfig
  SAF_ERROR_INVALIDINPUT_RADIOCFG_GUARD             = -15221,
  /// Invalid input parameter value for RadioID of tMKxFlushQueue
  SAF_ERROR_INVALIDINPUT_FLUSHQ_RADIOID             = -15300,
  /// Invalid input parameter value for ChannelID of tMKxFlushQueue
  SAF_ERROR_INVALIDINPUT_FLUSHQ_CHANNELID           = -15301,
  /// Invalid input parameter value for TxQueue of tMKxFlushQueue
  SAF_ERROR_INVALIDINPUT_FLUSHQ_TXQUEUE             = -15302,
  /// Invalid input parameter value for Version of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_VERSION              = -15400,
  /// Invalid input parameter value for CompensatorSel of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_COMPENSATORSEL       = -15401,
  /// INVALID INPUT parameter value for TxPowerCalMode of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TXPOWERCALMODE       = -15402,
  /// Invalid input parameter value for RSSICalMode of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_RSSICALMODE          = -15403,
  /// Invalid input parameter value for CompensatorReturn of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_COMPRETURN           = -15404,
  /// Invalid input parameter value Compensator.TxPowerThresh of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_COMPPOWERTHRESH      = -15405,
  /// Invalid input parameter value for Compensator.Alpha of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_COMPALPHA            = -15406,
  /// Invalid input parameter value for Compensator.Beta of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_COMPBETA             = -15407,
  /// Invalid input parameters value PALNA.Alpha + PALNA.Beta != 256
  SAF_ERROR_INVALIDINPUT_CALIB_COMPALPHABETA        = -15408,
  /// Invalid input parameter value for PALNA.TxPowerThresh of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_PALNAPOWERTHRESH     = -15409,
  /// Invalid input parameter value for PALNA.Alpha of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_PALNAALPHA           = -15410,
  /// Invalid input parameter value for PALNA.Beta of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_PALNABETA            = -15411,
  /// Invalid input parameters value PALNA.Alpha + PALNA.Beta != 256
  SAF_ERROR_INVALIDINPUT_CALIB_PALNAALPHABETA       = -15412,
  /// Invalid input parameter value for TxPowerExtraDrive of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_EXTRADRIVE           = -15413,
  /// Invalid input parameter value for TxPowerLimitMaxPower of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_LIMITMAXPOWER        = -15414,
  /// Invalid input parameter value for Temp SensorSource of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TEMPSENSOR           = -15415,
  /// Invalid input parameter value for I2CAddrSensor1 of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TEMPI2CADDRSENSOR1   = -15416,
  /// Invalid input parameter value for I2CAddrSensor2 of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TEMPI2CADDRSENSOR2   = -15417,
  /// Invalid input parameter value for PAEnableGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_PAENABLEGPIO         = -15418,
  /// Invalid input parameter value for LNAEnableGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_LNAENABLEGPIO        = -15419,
  /// Invalid input parameter value for RemotePAEnableGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_REMOTEPAGPIO         = -15420,
  /// Invalid input parameter value for C1GPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_C1GPIO               = -15421,
  /// Invalid input parameter value for TxClaimGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TXCLAIMGPIO          = -15422,
  /// Invalid input parameter value for CompensatorEnableGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_COMPENGPIO           = -15423,
  /// Invalid input parameter value for Timing.PAEnableLNADisable
  SAF_ERROR_INVALIDINPUT_CALIB_TIMINGPAEN           = -15424,
  /// Invalid input parameter value for Timing.BasebandStart of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TIMINGBBSTART        = -15425,
  /// Invalid input parameter value for Timing.AuxillaryADC of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TIMINGAUXADC         = -15426,
  /// Invalid input parameter value for Timing.RemotePADisable
  SAF_ERROR_INVALIDINPUT_CALIB_TIMINGREMOTEPA       = -15427,
  /// Invalid input parameter value for Timing.PADisable of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TIMINGPADIS          = -15428,
  /// Invalid input parameter value for Timing.LNAEnable of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TIMINGLNAEN          = -15429,
  /// Invalid input parameter value for OnePPSGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_1PPSGPIO             = -15430,
  /// Invalid input parameter value for CCAGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_CCAGPIO              = -15431,
  /// Invalid input parameter value for TxActiveGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_TXACTIVEGPIO         = -15432,
  /// Invalid input parameter value for RxActiveGPIO of tMKxCalibration
  SAF_ERROR_INVALIDINPUT_CALIB_RXACTIVEGPIO         = -15433,
  /// Invalid input parameter value for OtherRadioTxActiveGPIO
  SAF_ERROR_INVALIDINPUT_CALIB_OTHERTXGPIO          = -15434,
  /// Invalid input parameter value for OtherRadioRxActiveGPIO
  SAF_ERROR_INVALIDINPUT_CALIB_OTHERRXGPIO          = -15435,
  /// Invalid input parameter value for Ant1 ATemp.AuxADCInput (tMKxCalibration)
  SAF_ERROR_INVALIDINPUT_CALIB_ATEMPANT1AUXADC      = -15436,
  /// Invalid input parameter value for Ant2 ATemp.AuxADCInput (tMKxCalibration)
  SAF_ERROR_INVALIDINPUT_CALIB_ATEMPANT2AUXADC      = -15437,
  /// Invalid input parameter value for Temp.TempPAAnt1 of tMKxTemp
  SAF_ERROR_INVALIDINPUT_TEMP_PAANT1                = -15500,
  /// Invalid input parameter value for Temp.TempPAAnt2 of tMKxTemp
  SAF_ERROR_INVALIDINPUT_TEMP_PAANT2                = -15501,
  /// Invalid input parameter value for GPIO.Cmd of tMKxGPIO
  SAF_ERROR_INVALIDINPUT_GPIO_CMD                   = -15600,
  /// Invalid input parameter value for GPIO.PinNumber of tMKxGPIO
  SAF_ERROR_INVALIDINPUT_GPIO_PIN                   = -15601,
  /// Invalid input parameter value for GPIO.Value of tMKxGPIO
  SAF_ERROR_INVALIDINPUT_GPIO_VALUE                 = -15602,
  /// Invalid input parameter value for Cmd of tMKxFault
  SAF_ERROR_INVALIDINPUT_FAULT_CMD                  = -15700,
  /// Invalid input parameter value for CommandErrorCode of tMKxFault
  SAF_ERROR_INVALIDINPUT_FAULT_CMDERRORCODE         = -15701,

  // Errors detected within the LLC kernel module
  /// USB interface device not present
  SAF_ERROR_USB_DEVICE_NOT_PRESENT                  = -16100,
  /// The LLC kernel module encountered an invalid configuration of the SPI
  /// hardware while initialising the SPI interface
  SAF_ERROR_SPI_DEVICE_NOT_PRESENT                  = -16200,
  /// An operation by the LLC kernel module on the SPI interface timed out
  /// (1 second)
  SAF_ERROR_SPI_INTERFACE_TIMEOUT                   = -16201,
  /// The allocation by the LLC kernel module of a buffer to upload into,
  /// from the device failed
  SAF_ERROR_SPI_BUFFER_ALLOCATION_FAILURE           = -16202,
  /// The queue used by the LLC kernel module for input transfers using the
  /// SPI interface was exhausted
  SAF_ERROR_SPI_INPUT_QUEUE_EXHAUSTED               = -16203,
  /// An error was encountered by the LLC kernel module when examining the
  // contents of the output transfer queue used for SPI interface transfers
  SAF_ERROR_SPI_OUTPUT_QUEUE_ERROR                  = -16204,
  /// An invalid transfer structure was encountered by the LLC kernel module
  /// when trying to perform a transfer on the SPI interface
  SAF_ERROR_SPI_INVALID_TRANSFER_STRUCTURE          = -16205,
  /// An invalid output transfer structure was encountered by the the LLC
  /// kernel module when trying to perform a transfer on the SI interface
  SAF_ERROR_SPI_INVALID_OUTPUT_CONTEXT              = -16206,
  /// The ring buffer used by the LLC kernel module for output transfers
  /// on the SPI interface was overrun
  SAF_ERROR_SPI_BUFFER_OVERRUN                      = -16207,
  /// The LLC kernel module encountered a system error when requesting a
  /// transfer on the SPI interface
  SAF_ERROR_SPI_SYSTEM_ERROR                        = -16208,
  /// A critical structure used by the LLC kernel module when performing a
  /// transfer on the SPI interface was invalid
  SAF_ERROR_SPI_INVALID_CRITICAL_STRUCTURES         = -16209,
  /// The LLC kernel module encountered an invalid device ID when handling
  /// an interrupt from the SPI interface
  SAF_ERROR_SPI_INVALID_DEVICE_ID                   = -16210,
  /// The corrupted structure associated with a transfer on the SPI interface
  /// was encountered by the LLC kernel module
  SAF_ERROR_SPI_MEMORY_CORRUPTION                   = -16211,
  /// A memory allocation failure was encountered by the LLC kernel module
  /// when using the SPI interface
  SAF_ERROR_SPI_MEMORY_ALLOCATION_FAILURE           = -16212,
  /// The LLC kernel module encountered invalid SPI hardware configuration
  /// information when attempting to initialise the SPI interface
  SAF_ERROR_SPI_INIT_ERROR_DEVICE_NOT_PRESENT       = -16213,
  /// The LLC kernel module encountered already initialised SPI hardware
  /// when attempting to initialise the SPI interface
  SAF_ERROR_SPI_INIT_ERROR_DEVICE_ALREADY_SETUP     = -16214,
  /// The LLC kernel module was unable to allocate Tx cache memory
  /// when attempting to initialise the SPI interface
  SAF_ERROR_SPI_SYSTEM_CACHE_ALLOC_FAILURE          = -16215,
  /// The LLC kernel module encountered an initialisation failure of a
  /// list structure used with the SPI interface
  SAF_ERROR_SPI_SYSTEM_LIST_INIT_ERROR              = -16216,
  /// The LLC kernel module encountered an allocation failure of a
  /// list structure used with the SPI interface
  SAF_ERROR_SPI_SYSTEM_LIST_ITEM_ALLOC_ERROR        = -16217,
  /// The LLC kernel module encountered a failure of an operation on a
  /// list structure used with the SPI interface
  SAF_ERROR_SPI_SYSTEM_LIST_ITEM_ADD_ERROR          = -16218,
  /// The LLC kernel module encountered a system error when requesting a
  /// pointer to the SPI interface bus master structure
  SAF_ERROR_SPI_SYSTEM_BUS_TO_MASTER_ERROR          = -16219,
  /// The LLC kernel module SPI interface configuration was observed to be
  /// inconsistent with the system
  SAF_ERROR_SPI_SYSTEM_INVALID_CHIPSELECT           = -16220,
  /// The LLC kernel module encountered a system error when requesting the
  /// SPI device to be used be added to the SPI bus during initialisation
  SAF_ERROR_SPI_SYSTEM_ADD_DEVICE_ERROR             = -16221,
  /// The LLC kernel module encountered a system error when requesting
  /// access to the DAV pin used for interrupt based SPI operation
  SAF_ERROR_SPI_SYSTEM_DAV_PIN_REQUEST_ERROR        = -16222,
  /// The LLC kernel module encountered a system error when requesting
  /// the system associate the DAV pin with an IRQ handling function
  SAF_ERROR_SPI_SYSTEM_DAV_TO_IRQ_REQUEST_ERROR     = -16223,
  /// The LLC kernel module encountered an invalid SPI operating mode when
  /// initialising the SPI interface
  SAF_ERROR_SPI_INVALID_SPI_MODE                    = -16224,
  /// The LLC kernel module encountered an SPI interrupt while the module
  /// was not in an enabled state
  SAF_ERROR_SPI_INTERRUPT_BUT_NOT_ENABLED           = -16225,
  /// The LLC kernel module attempted to initialise the SDIO interface
  /// without it being required
  SAF_ERROR_SDIO_DEVICE_NOT_REQUIRED                = -16300,
  /// An operation by the LLC kernel module on the SDIO interface timed out
  /// (1 second)
  SAF_ERROR_SDIO_INTERFACE_TIMEOUT                  = -16301,
  /// The LLC kernel module encountered a failure when attempting to
  /// enable the SDIO interface interrupt essential for receving data
  SAF_ERROR_SDIO_ENABLE_INTERRUPT_FAILURE           = -16303,
  /// The LLC kernel module encountered a failure when attempting to
  /// disable the SDIO interface interrupt used for receving data
  SAF_ERROR_SDIO_DISABLE_INTERRUPT_FAILURE          = -16304,
  /// The LLC kernel module encountered a failure when attempting to clear
  /// the SDIO interface interrupt
  SAF_ERROR_SDIO_CLEAR_INTERRUPT_FAILURE            = -16305,
  /// The LLC kernel module encountered a failure when attempting to write
  /// to the SDIO device
  SAF_ERROR_SDIO_SYSTEM_WRITE_TO_DEVICE_FAILURE     = -16306,
  /// The LLC kernel module encountered a failure when attempting to read
  /// data from the SDIO device
  SAF_ERROR_SDIO_SYSTEM_READ_FROM_DEVICE_FAILURE    = -16308,
  /// The LLC kernel module was unable to register the SDIO unable to
  /// register the driver with the system
  SAF_ERROR_SDIO_SYSTEM_REGISTER_DRIVER_FAILURE     = -16309,
  /// The LLC kernel module encountered an initialisation failure of a
  /// list structure used with the SDIO interface
  SAF_ERROR_SDIO_SYSTEM_LIST_INIT_ERROR             = -16310,
  /// The LLC kernel module encountered an allocation failure of a
  /// list structure used with the SDIO interface
  SAF_ERROR_SDIO_SYSTEM_LIST_ITEM_ALLOC_ERROR       = -16311,
  /// The LLC kernel module encountered a failure of an operation on a
  /// list structure used with the SDIO interface
  SAF_ERROR_SDIO_SYSTEM_LIST_ITEM_ADD_ERROR         = -16312,
  /// The LLC kernel module encountered a failure when attempting to
  /// enable the SDIO interface through the system
  SAF_ERROR_SDIO_SYSTEM_FUNCTION_ENABLE_ERROR       = -16313,
  /// The LLC kernel module encountered a failure when attempting to
  /// set the SDIO interface data transfer block size
  SAF_ERROR_SDIO_SYSTEM_SET_BLOCK_SIZE_ERROR        = -16314,
  /// The LLC kernel module encountered a failure when attempting to
  /// read a byte from the SDIO device
  SAF_ERROR_SDIO_SYSTEM_READ_BYTE_ERROR             = -16315,
  /// The LLC kernel module encountered a failure when attempting to
  /// write a byte to the SDIO device
  SAF_ERROR_SDIO_SYSTEM_WRITE_BYTE_ERROR            = -16316,
  /// The corrupted structure associated with a transfer on the SDIO interface
  /// was encountered by the LLC kernel module
  SAF_ERROR_SDIO_MEMORY_CORRUPTION                  = -16317,
  /// The LLC kernel module was asked to send data out on the SDIO interface
  /// with the module not being in an enabled state
  SAF_ERROR_SDIO_OUT_NOT_ENABLED                    = -16318,
  /// The LLC kernel module was asked to receive data on the SDIO interface
  /// with the module not being in an enabled state
  SAF_ERROR_SDIO_IN_NOT_ENABLED                     = -16319,
  /// The LLC kernel module attempted to use the SDIO interface but
  /// system pointer to the device structure was NULL
  SAF_ERROR_SDIO_SYSTEM_FUNCTION_NOT_ENABLED        = -16320,
  /// The queue used by the LLC kernel module for input transfers using the
  /// SDIO interface was exhausted
  SAF_ERROR_SDIO_INPUT_QUEUE_EXHAUSTED              = -16321,
  /// The LLC kernel module encountered a request to read zero bytes from
  /// the device over the SDIO interface
  SAF_ERROR_SDIO_ZERO_UPLOAD_LENGTH                 = -16322,
  /// The LLC kernel module encountered a corrupted message that was read
  /// from the device over the SDIO interface
  SAF_ERROR_SDIO_CORRUPTED_INPUT_PACKET             = -16323,
  /// A memory allocation failure was encountered by the LLC kernel module
  /// when using the SDIO interface
  SAF_ERROR_SDIO_MEMORY_ALLOCATION_FAILURE          = -16324,
  /// The LLC kernel module encountered an invalid configuration of the
  /// Eth hardware while initialising the ETH interface
  SAF_ERROR_ETH_DEVICE_NOT_PRESENT                  = -16400,
  /// The corrupted structure associated with a transfer on the Eth interface
  /// was encountered by the LLC kernel module
  SAF_ERROR_ETH_MEMORY_CORRUPTION                   = -16401,
  /// The LLC kernel module encountered a corrupted message that was read
  /// from the device over the Eth interface
  SAF_ERROR_ETH_CORRUPTED_INPUT_PACKET              = -16402,
  /// The LLC kernel module encountered a missing socket when attempting to
  /// use the Eth interface
  SAF_ERROR_ETH_SOCKET_MISSING                      = -16403,
  /// The queue used by the LLC kernel module for input transfers using the
  /// Eth interface was exhausted
  SAF_ERROR_ETH_INPUT_QUEUE_EXHAUSTED               = -16404,
  /// A memory allocation failure was encountered by the LLC kernel module
  /// when using the Eth interface
  SAF_ERROR_ETH_MEMORY_ALLOCATION_FAILURE           = -16405,
  /// The LLC kernel module encountered an error when attempting to transmit
  /// data via the Eth interface
  SAF_ERROR_ETH_SYSTEM_TX_ERROR                     = -16406,
  /// The LLC kernel module encountered an error when attempting to receive
  /// data via the Eth interface
  SAF_ERROR_ETH_SYSTEM_RX_ERROR                     = -16407,
  /// The LLC kernel module encountered an error when attempting to create
  /// a socket during the initialsation of the the Eth interface
  SAF_ERROR_ETH_SYSTEM_RX_SOCKET_ERROR              = -16408,
  /// The LLC kernel module encountered an error when attempting to bind to
  /// a socket during the initialsation of the the Eth interface
  SAF_ERROR_ETH_SYSTEM_BIND_ERROR                   = -16409,
  /// The LLC kernel module encountered an error when attempting to set the
  /// scheduling of the socket receive thread during the initialsation of
  /// the the Eth interface
  SAF_ERROR_ETH_SYSTEM_SET_SCHEDULER_ERROR          = -16410,
  /// The LLC kernel module encountered an initialisation failure of a
  /// list structure used with the Eth interface
  SAF_ERROR_ETH_SYSTEM_LIST_INIT_ERROR              = -16411,
  /// The LLC kernel module encountered an allocation failure of a
  /// list structure used with the Eth interface
  SAF_ERROR_ETH_SYSTEM_LIST_ITEM_ALLOC_ERROR        = -16412,
  /// The LLC kernel module encountered a failure of an operation on a
  /// list structure used with the Eth interface
  SAF_ERROR_ETH_SYSTEM_LIST_ITEM_ADD_ERROR          = -16413,
  /// The LLC kernel module encountered an overflow error when transmitting
  /// data via the Eth interface
  SAF_ERROR_ETH_SYSTEM_OVERFLOW_ERROR               = -16414,
  /// An operation by the LLC kernel module on the Eth interface timed out
  /// (1 second)
  SAF_ERROR_ETH_INTERFACE_TIMEOUT                   = -16415,
  /// The LLC kernel module was asked to send data out on the Eth interface
  /// with the module not being in an enabled state
  SAF_ERROR_ETH_OUT_NOT_ENABLED                     = -16416,
  /// The final possible code (16 bits)
  SAF_ERROR_FINAL                                   = INT16_MIN,
} eSAFErrorCode;

/// MKx Radio
typedef enum
{
  /// Selection of Radio A of the MKX
  MKX_RADIO_A = 0U,
  /// Selection of Radio B of the MKX
  MKX_RADIO_B = 1U,
  // ...
  /// Used for array dimensioning
  MKX_RADIO_COUNT = 2U,
  /// Used for bounds checking
  MKX_RADIO_MAX = MKX_RADIO_COUNT - 1U
} eMKxRadio;
/// @copydoc eMKxRadio
typedef uint8_t tMKxRadio;

/// MKx Channel
typedef enum
{
  /// Indicates Channel Config 0 is selected
  MKX_CHANNEL_0 = 0U,
  /// Indicates Channel Config 1 is selected
  MKX_CHANNEL_1 = 1U,
  // ...
  /// Used for array dimensioning
  MKX_CHANNEL_COUNT = 2U,
  /// Used for bounds checking
  MKX_CHANNEL_MAX = MKX_CHANNEL_COUNT - 1U

} eMKxChannel;
/// @copydoc eMKxChannel
typedef uint8_t tMKxChannel;

/// MKx Bandwidth
typedef enum
{
  /// Indicates 10 MHz
  MKXBW_10MHz = 10U,
  /// Indicates 20 MHz
  MKXBW_20MHz = 20U
} eMKxBandwidth;
/// @copydoc eMKxBandwidth
typedef uint8_t tMKxBandwidth;

/// The channel's centre frequency [MHz]
typedef uint16_t tMKxChannelFreq;

/**
 * MKx dual radio transmit control
 * Bitfields to controls transmit behaviour according to activity on the
 * other radio (inactive in single radio configurations)
 */
typedef enum
{
  /// Do not constrain transmissions
  MKX_TXC_NONE    = 0x0,
  /// Prevent transmissions when other radio is transmitting
  MKX_TXC_TX      = 0x1,
  /// Prevent transmissions when other radio is receiving
  MKX_TXC_RX      = 0x2,
  /// Prevent transmissions when other radio is transmitting or receiving
  MKX_TXC_TXRX    = MKX_TXC_TX | MKX_TXC_RX,
  /// Default behaviour
  MKX_TXC_DEFAULT = MKX_TXC_TX
} eMKxDualTxControl;
/// @copydoc eMKxDualTxControl
typedef uint8_t tMKxDualTxControl;

/**
 * MKx Modulation and Coding scheme
 */
typedef enum
{
  /// Rate 1/2 BPSK
  MKXMCS_R12BPSK = 0xB,
  /// Rate 3/4 BPSK
  MKXMCS_R34BPSK = 0xF,
  /// Rate 1/2 QPSK
  MKXMCS_R12QPSK = 0xA,
  /// Rate 3/4 QPSK
  MKXMCS_R34QPSK = 0xE,
  /// Rate 1/2 16QAM
  MKXMCS_R12QAM16 = 0x9,
  /// Rate 3/4 16QAM
  MKXMCS_R34QAM16 = 0xD,
  /// Rate 2/3 64QAM
  MKXMCS_R23QAM64 = 0x8,
  /// Rate 3/4 64QAM
  MKXMCS_R34QAM64 = 0xC,
  /// Use default data rate
  MKXMCS_DEFAULT = 0x0,
  /// Use transmit rate control (currently unused)
  MKXMCS_TRC = 0x1
} eMKxMCS;
/// @copydoc eMKxMCS
typedef uint8_t tMKxMCS;

/// Tx & Rx power of frame, in 0.5dBm units.
typedef enum
{
  /// Selects the PHY maximum transmit power
  MKX_POWER_TX_MAX      = INT16_MAX,
  /// Selects the PHY minimum transmit power
  MKX_POWER_TX_MIN      = INT16_MIN,
  /// Selects the PHY default transmit power level
  MKX_POWER_TX_DEFAULT  = MKX_POWER_TX_MIN + 1,
  /// Indicates when the Rx power reported is invalid as antenna is disabled
  MKX_POWER_RX_DISABLED = INT16_MIN
} eMKxPower;
/// @copydoc eMKxPower
typedef int16_t tMKxPower;

/**
 * MKx Antenna Selection
 */
typedef enum
{
  /// Invalid antenna
  MKX_ANT_INVALID = 0U,
  /// Transmit packet on antenna 1
  MKX_ANT_1       = 1U,
  /// Transmit packet on antenna 2 (when available).
  MKX_ANT_2       = 2U,
  /// Transmit packet on both antenna
  MKX_ANT_1AND2   = MKX_ANT_1 | MKX_ANT_2,
  /// Selects the default (ChanConfig) transmit antenna setting
  MKX_ANT_DEFAULT = 4U
} eMKxAntenna;
/// @copydoc eMKxAntenna
typedef uint8_t tMKxAntenna;

/// Array index for Antenna 1 selection
#define ANT1_INDEX (uint8_t)((tMKxAntenna)MKX_ANT_1 - (tMKxAntenna)MKX_ANT_1)
/// Array index for Antenna 2 selection
#define ANT2_INDEX (uint8_t)((tMKxAntenna)MKX_ANT_2 - (tMKxAntenna)MKX_ANT_1)
/// Typedef for AntennaIndex
typedef uint8_t tMKxAntennaIndex;
/// Number of antennas that are present for the MKX
#define MKX_ANT_COUNT 2U

/**
 * MKx TSF
 * Indicates absolute 802.11 MAC time in microseconds
 */
typedef uint64_t tMKxTSF;

/**
 * MKx Rate sets
 * Each bit indicates if corresponding MCS rate is supported
 */
typedef enum
{
  /// Rate 1/2 BPSK rate mask
  MKX_RATE12BPSK_MASK = 0x01,
  /// Rate 3/4 BPSK rate mask
  MKX_RATE34BPSK_MASK = 0x02,
  /// Rate 1/2 QPSK rate mask
  MKX_RATE12QPSK_MASK = 0x04,
  /// Rate 3/4 QPSK rate mask
  MKX_RATE34QPSK_MASK = 0x08,
  /// Rate 1/2 16QAM rate mask
  MKX_RATE12QAM16_MASK = 0x10,
  /// Rate 2/3 64QAM rate mask
  MKX_RATE23QAM64_MASK = 0x20,
  /// Rate 3/4 16QAM rate mask
  MKX_RATE34QAM16_MASK = 0x40
} eMKxRate;
/// @copydoc eMKxRate
typedef uint8_t tMKxRate;

/**
 * MKx 802.11 service class specification.
 */
typedef enum
{
  /// Packet should be (was) transmitted using normal ACK policy
  MKX_QOS_ACK = 0x00U,
  /// Packet should be (was) transmitted without Acknowledgement.
  MKX_QOS_NOACK = 0x01U
} eMKxService;
/// @copydoc eMKxService
typedef uint8_t tMKxService;

/**
 * MKx Additional MAC layer tx control
 * These bits signal to the radio that special Tx behaviour is required
 */
typedef enum
{
  /// Do not require any special behaviour
  MKX_REGULAR_TRANSMISSION                  = 0x00,
  /// Do not modify the sequence number field
  MKX_DISABLE_MAC_HEADER_UPDATES_SEQCTRL    = 0x01,
  /// Do not modify the duration ID field
  MKX_DISABLE_MAC_HEADER_UPDATES_DURATIONID = 0x02,
  /// Do not modify the Ack Policy field
  MKX_DISABLE_MAC_HEADER_UPDATES_ACKPOLICY  = 0x04,
  /// Do not modify the Retry field and set Max retries to zero
  MKX_DISABLE_MAC_HEADER_UPDATES_RETRY      = 0x08,
  /// Force the use of RTS/CTS with this packet
  MKX_FORCE_RTSCTS                          = 0x10
} eMKxTxCtrlFlags;
/// @copydoc eMKxTxCtrlFlags
typedef uint8_t tMKxTxCtrlFlags;

/**
 * MKx Transmit Descriptor. This header is used to control how the data packet
 * is transmitted by the LLC. This is the header used on all transmitted
 * packets.
 */
typedef struct MKxTxPacketData
{
  /// Indicate the radio that should be used (Radio A or Radio B)
  tMKxRadio RadioID;
  /// Indicate the channel config for the selected radio
  tMKxChannel ChannelID;
  /// Indicate the antennas upon which packet should be transmitted
  /// (may specify default)
  tMKxAntenna TxAntenna;
  /// Indicate the MCS to be used (may specify default)
  tMKxMCS MCS;
  /// Indicate the power to be used (may specify default)
  tMKxPower TxPower;
  /// Additional control over the transmitter behaviour (must be set to zero
  /// for normal operation)
  tMKxTxCtrlFlags TxCtrlFlags;
  // Reserved (for 64 bit alignment and internal processing)
  uint8_t Reserved0;
  /// Indicate the expiry time as an absolute MAC time in microseconds
  /// (0 means never)
  tMKxTSF Expiry;
  /// Length of the frame (802.11 Header + Body, not including FCS)
  uint16_t TxFrameLength;
  // Reserved (for 32 bit alignment and internal processing)
  uint16_t Reserved1;
  /// Frame (802.11 Header + Body, not including FCS)
  uint8_t TxFrame[];
} __attribute__((__packed__)) tMKxTxPacketData;

/**
 * MKx Transmit Packet format.
 */
typedef struct MKxTxPacket
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  /// Tx Packet control and frame data
  tMKxTxPacketData TxPacketData;
} __attribute__((__packed__)) tMKxTxPacket;

/**
 * Transmit Event Data. This is the structure of the data field for
 * MKxIFMsg messages of type TxEvent.
 */
typedef struct MKxTxEventData
{
  /// Transmit status (transmitted/retired), @ref eMKxStatus
  int16_t TxStatus;
  /// 802.11 MAC sequence number of the transmitted frame
  uint16_t MACSequenceNumber;
  /// The TSF when the packet was transmitted or retired
  tMKxTSF TxTime;
  /// Delay (picoseconds) between end of Tx Data frame and start of Rx Ack frame
  uint32_t AckResponseDelay_ps;
  /// Delay (picoseconds) between end of Tx RTS frame and start of Rx CTS frame,
  /// reserved for non-CTS transmissions
  uint32_t CTSResponseDelay_ps;
  /// Time (us) between the arrival of the packet at the MAC and its Tx
  uint32_t MACDwellTime;
  /// Short packet retry counter
  uint8_t NumShortRetries;
  /// Long packet retry counter
  uint8_t NumLongRetries;
  /// Destination address of the transmitted frame
  uint8_t DestAddress[6];
  /// Reserved for future use
  uint32_t Reserved0;
  /// Reserved for future use
  uint32_t Reserved1;
} __attribute__((__packed__)) tMKxTxEventData;

/**
 * MKx Transmit Event format.
 */
typedef struct MKxTxEvent
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  /// Tx Event Data
  tMKxTxEventData TxEventData;
} __attribute__((__packed__)) tMKxTxEvent;

/**
 * MKx Receive descriptor and frame.
 * This header is used to pass receive packet meta-information from
 * the LLC to upper-layers. This header is prepended to all received packets.
 * If only a single receive  power measure is required, then simply take the
 * maximum power of Antenna A and B.
 */
typedef struct MKxRxPacketData
{
  /// Indicate the radio that should be used (Radio A or Radio B)
  tMKxRadio RadioID;
  /// Indicate the channel config for the selected radio
  tMKxChannel ChannelID;
  /// Indicate the data rate that was used
  tMKxMCS MCS;
  // Indicates FCS passed for received frame (1=Pass, 0=Fail)
  uint8_t FCSPass;
  /// Indicate the received power on Antenna 1
  tMKxPower RxPowerAnt1;
  /// Indicate the received power on Antenna 2
  tMKxPower RxPowerAnt2;
  /// Indicate the receiver noise on Antenna 1
  tMKxPower RxNoiseAnt1;
  /// Indicate the receiver noise on Antenna 2
  tMKxPower RxNoiseAnt2;
  /// Estimated frequency offset of rx frame in Hz (with respect to local freq)
  int32_t RxFreqOffset;
  /// MAC Rx Timestamp, local MAC TSF time at which packet was received
  tMKxTSF RxTSF;
  /// Length of the Frame (802.11 Header + Body, including FCS)
  uint16_t RxFrameLength;
  /// Channel centre frequency on which this packet was received
  tMKxChannelFreq ChannelFreq;

  /// Reserved for future use
  uint32_t Reserved1;
  /// Reserved for future use
  uint32_t Reserved2;
  /// Reserved for future use
  uint32_t Reserved3;
  /// Reserved for future use
  uint32_t Reserved4;

  /// Frame (802.11 Header + Body, including FCS)
  uint8_t RxFrame[];
} __attribute__((__packed__)) tMKxRxPacketData;

/**
 * MKx receive packet format.
 */
typedef struct MKxRxPacket
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  /// Rx Packet control and frame data
  tMKxRxPacketData RxPacketData;
} __attribute__((__packed__)) tMKxRxPacket;

/// MKx SetTSF command type
typedef enum MKxSetTSFCmd {
  /// UTC time provided corresponds to the UTC time at 1PPS event
  UTC_AT_1PPS = 1,
  /// UTC time provided corresponds to the TSF timestamp provided
  UTC_AT_TSF = 2
} eMKxSetTSFCmd;
/// @copydoc eMKxSetTSFCmd
typedef uint8_t tMKxSetTSFCmd;

/**
 * Set TSF data
 * Data for setting the time synchronisation function (TSF) to UTC time.
 * The TSF can be set to
 * - UTC time at GPS 1PPS (obtained from NMEA data)
 * - UTC time at TSF Timestamp (through the use of timing advertisements)
 */
 typedef struct MKxSetTSFData
{
  /// Selects the UTC to with 1PPS or TSF Timestamp
  tMKxSetTSFCmd Cmd;
  // Reserved (for 32 bit alignment)
  uint8_t Reserved0;
  uint8_t Reserved1;
  uint8_t Reserved2;
  /// UTC Time at either previous 1PPS event or at TSF Timestamp
  tMKxTSF UTC;
  /// TSF Timestamp at UTC
  tMKxTSF TSF;
} __attribute__((__packed__)) tMKxSetTSFData;

/**
 * MKx Set TSF message format
 */
typedef struct MKxSetTSF
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// SetTSF Message Data
  tMKxSetTSFData SetTSFData;
} __attribute__((__packed__)) tMKxSetTSF;

/**
 * MKx Get TSF message format
 */
typedef struct MKxGetTSF
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// GetTSF Message Data (current TSF value)
  tMKxTSF TSF;
} __attribute__((__packed__)) tMKxGetTSF;

/// Transmit queues (in priority order, where lowest is highest priority)
typedef enum
{
  MKX_TXQ_NON_QOS = 0, ///< Non QoS (for WSAs etc.)
  MKX_TXQ_AC_VO = 1,   ///< Voice
  MKX_TXQ_AC_VI = 2,   ///< Video
  MKX_TXQ_AC_BE = 3,   ///< Best effort
  MKX_TXQ_AC_BK = 4,   ///< Background
  /// For array dimensioning
  MKX_TXQ_COUNT = 5,
  /// Command to flush all queues (see @ref tMKxFlushQueue)
  MKX_TXQ_FLUSHALL = MKX_TXQ_COUNT,
  /// For bounds checking
  MKX_TXQ_MAX = MKX_TXQ_COUNT - 1
} eMKxTxQueue;
/// @copydoc eMKxTxQueue
typedef uint8_t tMKxTxQueue;

/**
 * MKx FlushQueue message format
 */
typedef struct MKxFlushQueue
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// Indicate the radio that should be used (Radio A or Radio B)
  tMKxRadio RadioID;
  /// Indicate the channel for the selected radio
  tMKxChannel ChannelID;
  /// Queue selection to be flush (MKX_TXQ_FLUSHALL for all)
  tMKxTxQueue TxQueue;
  /// Padding to ensure message size is multiple of 4 bytes
  uint8_t Pad;
} __attribute__((__packed__)) tMKxFlushQueue;

/**
 * MKx Rate Set. See @ref eMKxRate for bitmask for enabled rates
 */
typedef uint8_t tMKxRateSet[8];

/// Address matching control bits
/// (bit 0) = ResponseEnable
/// (bit 1) = BufferEnableCtrl
/// (bit 2) = BufferEnableBadFCS
/// (bit 3) = LastEntry
/// (bit 4) = BufferDuplicate
typedef enum
{
  /// ResponseEnable -- Respond with ACK when a DATA frame is matched.
  MKX_ADDRMATCH_RESPONSE_ENABLE = (1U << 0U),
  /// BufferEnableCtrl -- Buffer control frames that match.
  MKX_ADDRMATCH_ENABLE_CTRL     = (1U << 1U),
  /// BufferEnableBadFCS -- Buffer frames even if FCS error was detected.
  MKX_ADDRMATCH_ENABLE_BAD_FCS  = (1U << 2U),
  /// LastEntry -- Indicates this is the last entry in the table.
  MKX_ADDRMATCH_LAST_ENTRY      = (1U << 3U),
  /// BufferDuplicate -- Buffer duplicate frames
  MKX_ADDRMATCH_DUPLICATE       = (1U << 4U)
} eMKxAddressMatchingCtrl;

/**
 * @brief Receive frame address matching structure
 *
 * General operation of the MKx on receive frame:
 * - bitwise AND of 'Mask' and the incoming frame's DA (DA not modified)
 * - equality check between 'Addr' and the masked DA
 * - If equal: continue
 *  - If 'ResponseEnable' is set: Send 'ACK'
 *  - If 'BufferEnableCtrl' is set: Copy into internal buffer
 *                                  & deliver via RxInd() if FCS check passes
 *  - If 'BufferEnableBadFCS' is set: Deliver via RxInd() even if FCS check
 *    fails
 *
 * To receive broadcast frames:
 * - Addr = 0XFFFFFFFFFFFFULL
 * - Mask = 0XFFFFFFFFFFFFULL
 * - MatchCtrl = 0x0000
 * To receive anonymous IEEE1609 heartbeat (multicast) frames:
 * - Addr = 0X000000000000ULL
 * - Mask = 0XFFFFFFFFFFFFULL
 * - MatchCtrl = 0x0000
 * To receive valid unicast frames for 01:23:45:67:89:AB (our MAC address)
 * - Addr = 0XAB8967452301ULL
 * - Mask = 0XFFFFFFFFFFFFULL
 * - MatchCtrl = 0x0001
 * To monitor the channel in promiscuous mode (including failed FCS frames,
 * and all duplicates):
 * - Addr = 0X000000000000ULL
 * - Mask = 0X000000000000ULL
 * - MatchCtrl = 0x0016
 */
typedef struct MKxAddressMatching
{
#ifndef LLC_NO_BITFIELDS
  /// 48 bit mask to apply to DA before comparing with Addr field
  uint64_t Mask:48;
  uint64_t Pad0:16; // Align to 64 bit boundary

  /// 48 bit MAC address to match after masking
  uint64_t Addr:48;
  /// Bitmask see @ref eMKxAddressMatchingCtrl
  uint64_t MatchCtrl:8;
  uint64_t Pad1:8; // Align to 64 bit boundary
#else
  uint8_t Mask[6];
  uint16_t Reserved0;
  uint8_t Addr[6];
  uint16_t MatchCtrl;
#endif
} __attribute__((__packed__)) tMKxAddressMatching;

/// MKx transmit queue configuration
typedef struct MKxTxQConfig
{
  /// Arbitration inter-frame-spacing (values of 0 to 16)
  uint8_t AIFS;
  /// Padding to ensure 32 bit alignment
  uint8_t Pad;
  /// Contention window min
  uint16_t CWMIN;
  /// Contention window max
  uint16_t CWMAX;
  /// TXOP duration limit [ms]
  uint16_t TXOP;
} __attribute__((__packed__)) tMKxTxQConfig;

/// PHY specific config
typedef struct MKxChanConfigPHY
{
  /// Channel centre frequency (in MHz) that should be used e.g. 5000 + (5*172)
  tMKxChannelFreq ChannelFreq;
  /// Indicate if channel is 10 MHz or 20 MHz
  tMKxBandwidth Bandwidth;
  /// Default Transmit antenna configuration
  /// (can be overridden in @ref tMKxTxPacket)
  /// Antenna selection used for transmission of ACK/CTS
  tMKxAntenna TxAntenna;
  /// Receive antenna configuration
  tMKxAntenna RxAntenna;
  /// Indicate the default data rate that should be used
  tMKxMCS DefaultMCS;
  /// Indicate the default transmit power that should be used
  /// Power setting used for Transmission of ACK/CTS
  tMKxPower DefaultTxPower;
} __attribute__((__packed__)) tMKxChanConfigPHY;

/// MAC specific config
typedef struct MKxChanConfigMAC
{
  /// Dual Radio transmit control (inactive in single radio configurations)
  tMKxDualTxControl DualTxControl;
  /// The RSSI power detection threshold for carrier sense [dBm]
  int8_t CSThreshold;
  /// The CBR threshold [dBm]
  int8_t CBRThreshold;
  /// 32-bit alignment
  uint8_t Padding[3];
  /// Slot time/duration, per 802.11-2012
  uint16_t SlotTime;
  /// Distributed interframe space, per 802.11-2012
  uint16_t DIFSTime;
  /// Short interframe space, per 802.11-2012
  uint16_t SIFSTime;
  /// Duration to wait after an erroneously received frame,
  /// before beginning slot periods
  /// @note this should be set to EIFS - DIFS
  uint16_t EIFSTime;
  /// Threshold at which RTS/CTS is used for unicast packets (bytes).
  uint16_t RTSCTSThreshold;
  /// Retry limit for short unicast transmissions
  uint16_t ShortRetryLimit;
  /// Retry limit for long unicast transmissions
  uint16_t LongRetryLimit;
  /// Per queue configuration
  tMKxTxQConfig TxQueue[MKX_TXQ_COUNT];
  /// Address matching filters: DA, broadcast, unicast & multicast
  tMKxAddressMatching AMSTable[AMS_TABLE_COUNT];
} __attribute__((__packed__)) tMKxChanConfigMAC;

/// LLC (WMAC) specific config
typedef struct MKxChanConfigLLC
{
  /// Duration of this channel interval, in microseconds. Zero means forever.
  /// Also sets the interval between stats messages sent.
  uint32_t IntervalDuration;
  /// Duration of guard interval upon entering this channel, in microseconds
  uint32_t GuardDuration;
} __attribute__((__packed__)) tMKxChanConfigLLC;

/**
 * MKx channel configuration
 */
typedef struct MKxChanConfig
{
  /// PHY specific config
  struct MKxChanConfigPHY PHY;
  /// MAC specific config
  struct MKxChanConfigMAC MAC;
  /// LLC (WMAC) specific config
  struct MKxChanConfigLLC LLC;
} __attribute__((__packed__)) tMKxChanConfig;

/**
 * MKxRadioMode bitfield configuration
 */
typedef enum
{
  /// Radio is off
  MKX_MODE_OFF       = 0U,
  /// Radio is using channel config 0 configuration only
  MKX_MODE_CHANNEL_0 = 1U,
  /// Radio is enabled to use channel config 1 configuration only
  MKX_MODE_CHANNEL_1 = 2U,
  /// Radio is enabled to channel switch between config 0 & config 1 configs
  MKX_MODE_SWITCHED  = MKX_MODE_CHANNEL_0 | MKX_MODE_CHANNEL_1,
  /// Radio configuration read request
  MKX_MODE_READ_ONLY = 0x8080U
} eRadioMode;
/// @copydoc eRadioMode
typedef uint16_t tMKxRadioMode;

/// MKx per radio configuration
typedef struct MKxRadioConfigData
{
  /// Operation mode of the radio
  tMKxRadioMode Mode;
  /// System clock tick rate in MHz, a read-only field
  uint16_t SystemTickRateMHz;
  /// Channel Configurations for this radio
  tMKxChanConfig ChanConfig[MKX_CHANNEL_COUNT];
} __attribute__((__packed__)) tMKxRadioConfigData;

/**
 * MKx configuration message format.
 */
typedef struct MKxRadioConfig
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  /// Radio configuration data
  tMKxRadioConfigData RadioConfigData;
} __attribute__((__packed__)) tMKxRadioConfig;

/// Tx Queue stats counters
typedef struct MKxTxQueueStats
{
  /// Number of frames submitted via MKx_TxReq() to the current queue
  uint32_t    TxReqCount;
  /// Number of frames successfully transmitted (excluding retries)
  uint32_t    TxCnfCount;
  /// Number of frames unsuccessfully transmitted (excluding retries)
  uint32_t    TxErrCount;
  /// Number of packets transmitted on the channel (including retries)
  uint32_t    TxValid;
  /// Number of internal collisions experienced
  uint32_t    InternalCollisions;
  /// Number of packets in the queue
  uint32_t    TxPending;
} __attribute__((__packed__)) tMKxTxQueueStats;

/// Channel stats counters
typedef struct MKxChannelStats
{
  /// Number of frames submitted via MKx_TxReq()
  uint32_t    TxReq;
  /// Number of Tx frames discarded by the MKx
  uint32_t    TxFail;
  /// Number of frames successfully transmitted (excluding retries)
  uint32_t    TxCnf;
  /// Number of frames unsuccessfully transmitted (excluding retries)
  uint32_t    TxErr;
  /// Number of packets transmitted on the channel (including retries)
  uint32_t    TxValid;
  /// Number of frames delivered via MKx_RxInd()
  uint32_t    RxInd;
  /// Number of Rx frames discarded by the MKx
  uint32_t    RxFail;
  /// Total number of duplicate (unicast) packets received on the channel
  uint32_t    RxDup;
  /// Per queue statistics
  tMKxTxQueueStats TxQueue[MKX_TXQ_COUNT];
  /// Medium busy time.  Number of us that the medium is declared busy over
  /// the last measurement period.  Medium is declared busy during Tx, Rx and
  /// Nav events.
  uint32_t MediumBusyTime;
  /// Proportion of time which the radio is considered busy over the last
  /// measurement period. (255 = 100%)
  uint8_t ChannelBusyRatio;
  /// Average idle period power [dBm]
  int8_t AverageIdlePower;
  /// Padding for 32 bit alignment
  uint16_t Pad;
} __attribute__((__packed__)) tMKxChannelStats;

/// Radio level stats counters
typedef struct MKxRadioStatsData
{
  /// Per channel context statistics
  tMKxChannelStats Chan[MKX_CHANNEL_COUNT];
  /// TSF timer value at the end of the last measurement period [us]
  tMKxTSF TSF;
} __attribute__((__packed__)) tMKxRadioStatsData;

/**
 * MKx Radio stats format
 */
typedef struct MKxRadioStats
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  /// Radio Stats Data
  tMKxRadioStatsData RadioStatsData;
} __attribute__((__packed__)) tMKxRadioStats;

/**
 * C2X Security API
 */

/// Sequence number used to identify security commands and match their responses
typedef uint16_t tMKxC2XSecUSN;

/// Enumeration for the security instruction types
typedef enum MKxC2XSecInst
{
  /// Message instruction to verify the signature of a hash message
  MKXC2XSEC_INST_VERIFY_MESSAGE                = 0U,
  /// Message instruction to decompress a public key
  MKXC2XSEC_INST_DECOMPRESS_PUBLIC_KEY         = 1U,
  /// Message instruction to reconstruct a public key
  MKXC2XSEC_INST_RECONSTRUCT_PUBLIC_KEY        = 2U,
  /// Message instruction to verify a message with a compressed public key
  MKXC2XSEC_INST_DECOMPRESS_AND_VERIFY_MESSAGE = 3U,

  MKXC2XSEC_INST_COUNT
} eMKxC2XSecInst;
/// Security instruction type
typedef uint16_t tMKxC2XSecInst;

/// Security command return codes
typedef enum MKxC2XSecErrorCode
{
  /// The function completed successfully.
  MKXC2XSEC_SUCCESS                  = 0U,
  /// The INS value is not supported by the applet.
  MKXC2XSEC_INS_NOT_SUPPORTED        = 1U,
  /// The value of parameter LC is invalid.
  MKXC2XSEC_INVALID_LENGTH           = 2U,
  /// CurveID field is invalid
  MKXC2XSEC_CURVEID_INVALID          = 3U,
  /// The data field of the command contains wrong data.
  MKXC2XSEC_WRONG_DATA               = 4U,
  /// An exception occurred of which no precise diagnosis is available. This
  /// error code should also be used in case security intrusion is detected.
  MKXC2XSEC_NO_PRECISE_DIAGNOSIS     = 5U,
} eMKxC2XSecErrorCode;
/// Security command return code
typedef uint16_t tMKxC2XSecErrorCode;

/// Security verification results
typedef enum MKxC2XSecVerifyResult
{
  MKXC2XSEC_VERIFY_SUCCESS = 0U,
  MKXC2XSEC_VERIFY_FAILURE = 1U
} eMKxC2XSecVerifyResult;
/// Security verification result
typedef uint32_t tMKxC2XSecVerRes;

/// ECDSA Security Curve Identifiers
typedef enum MKxC2XSecCurveID
{
  MKXC2XSEC_CID_NIST256        = 0U, /// curve type NIST256p
  MKXC2XSEC_CID_BRAINPOOL256R1 = 1U, /// curve type BRAINPOOL256r1
  MKXC2XSEC_CID_BRAINPOOL384R1 = 2U, /// curve type BRAINPOOL384r1

  MKXC2XSEC_CID_COUNT
} eMKxC2XSecCurveID;
/// Public key curve id
typedef uint16_t tMKxC2XSecCID;

/// Public key signature 256 bit
typedef uint8_t tMKxC2XSecSig256[32];
/// Public key signature 384 bit
typedef uint8_t tMKxC2XSecSig384[48];

/// Public key hash 256 bit
typedef uint8_t tMKxC2XSecHash256[32];
/// Public key hash 384 bit
typedef uint8_t tMKxC2XSecHash384[48];

/// Public key coordinate 256 bit
typedef uint8_t tMKxC2XSecCoord256[32];
/// Public key coordinate 384 bit
typedef uint8_t tMKxC2XSecCoord384[48];

/// Public key pair 256 bit
typedef struct MKxC2XSecPair256
{
  /// X coordinate for elliptical signature
  tMKxC2XSecCoord256 X;
  /// Y coordinate for elliptical signature
  tMKxC2XSecCoord256 Y;
}__attribute__((__packed__)) tMKxC2XSecPair256;

/// Public key pair 384 bit
typedef struct MKxC2XSecPair384
{
  /// X coordinate for elliptical signature
  tMKxC2XSecCoord384 X;
  /// Y coordinate for elliptical signature
  tMKxC2XSecCoord384 Y;
}__attribute__((__packed__)) tMKxC2XSecPair384;

/// Compressed public key 256 bit
typedef struct MKxC2XSecCompPubKey256
{
  /// X coordinate for elliptical signature
  tMKxC2XSecCoord256 X;
  /// The least significant _bit_ of the Y coordinate
  uint8_t Ybit;
}__attribute__((__packed__)) tMKxC2XSecCompPubKey256;

/// Compressed public key 384 bit
typedef struct MKxC2XSecCompPubKey384
{
  /// X coordinate for elliptical signature
  tMKxC2XSecCoord384 X;
  /// The least significant _bit_ of the Y coordinate
  uint8_t Ybit;
}__attribute__((__packed__)) tMKxC2XSecCompPubKey384;

/**
 * C2X security command message
 * +-----+-----+-----+-----+---...---+
 * | USN | INS | CID | LC  | Payload |
 * +-----+-----+-----+-----+---...---+
 *    2     2     2     2    'LC - 8'    
 */

/// C2X Security command header
typedef struct MKxC2XSecCmdHdr
{
  /// Value used to identify this command and its response
  tMKxC2XSecUSN USN;
  /// C2XSec command instruction
  tMKxC2XSecInst INS;
  /// The ECC curve used in the command
  tMKxC2XSecCID CurveID;
  /// The length of the security command including the header
  uint16_t LC;
  /// The payload of the command
  uint8_t Data[];
}__attribute__((__packed__)) tMKxC2XSecCmdHdr;

/// Verify Signature of Hash 256 bit
typedef struct MKxC2XSecVSOH256
{
  /// Public key of the entity that created the signature
  tMKxC2XSecPair256 PubKey;
  /// Hash protected by signature
  tMKxC2XSecHash256 E;
  /// The signature over the hash, to be verified (R)
  tMKxC2XSecSig256 R;
  /// The signature over the hash, to be verified (S)
  tMKxC2XSecSig256 S;
}__attribute__((__packed__)) tMKxC2XSecVSOH256;

/// Verify Signature of Hash 384 bit
typedef struct MKxC2XSecVSOH384
{
  tMKxC2XSecPair384 PubKey;
  /// Hash protected by signature
  tMKxC2XSecHash384 E;
  /// The signature over the hash, to be verified (R)
  tMKxC2XSecSig384 R;
  /// The signature over the hash, to be verified (S)
  tMKxC2XSecSig384 S;
}__attribute__((__packed__)) tMKxC2XSecVSOH384;

/// Decompress public key and Verify Signature of Hash 256 bit
typedef struct MKxC2XSecDPKVSOH256
{
  /// ECC Public key to decompressed
  tMKxC2XSecCompPubKey256 CompPubKey;
  /// Padding for 32-bit alignment
  uint8_t Padding[3];
  /// Hash protected by signature
  tMKxC2XSecHash256 E;
  /// The signature over the hash, to be verified (R)
  tMKxC2XSecSig256 R;
  /// The signature over the hash, to be verified (S)
  tMKxC2XSecSig256 S;
}__attribute__((__packed__)) tMKxC2XSecDPKVSOH256;

/// Decompress public key and Verify Signature of Hash 384 bit
typedef struct MKxC2XSecDPKVSOH384
{
  /// ECC Public key to decompressed
  tMKxC2XSecCompPubKey384 CompPubKey;
  /// Padding for 32-bit alignment
  uint8_t Padding[3];
  /// Hash protected by signature
  tMKxC2XSecHash384 E;
  /// The signature over the hash, to be verified (R)
  tMKxC2XSecSig384 R;
  /// The signature over the hash, to be verified (S)
  tMKxC2XSecSig384 S;
}__attribute__((__packed__)) tMKxC2XSecDPKVSOH384;

/// Decompress Public Key 256 bit
typedef struct MKxC2XSecDPK256
{
  /// ECC Public key to decompressed
  tMKxC2XSecCompPubKey256 CompPubKey;
  /// Padding for 32-bit alignment
  uint8_t Padding[3];
}__attribute__((__packed__)) tMKxC2XSecDPK256;

/// Decompress Public Key 384 bit
typedef struct MKxC2XSecDPK384
{
  /// ECC Public key to decompressed
  tMKxC2XSecCompPubKey384 CompPubKey;
  /// Padding for 32-bit alignment
  uint8_t Padding[3];
}__attribute__((__packed__)) tMKxC2XSecDPK384;

/// Reconstruct ECC Public Key 256 bit
typedef struct MKxC2XSecREPK256
{
  /// Hash value used in derivation of ECC public key
  tMKxC2XSecHash256 hvij;
  /// Public reconstruction value used in derivation of ECC public key
  tMKxC2XSecPair256 RVij;
  /// Public key of Pseudonym CA used in derivation of the ECC public key
  tMKxC2XSecPair256 Spca;
}__attribute__((__packed__)) tMKxC2XSecREPK256;

/// Reconstruct ECC Public Key 384 bit
typedef struct MKxC2XSecREPK384
{
  /// Hash value used in derivation of ECC public key
  tMKxC2XSecHash384 hvij;
  /// Public reconstruction value used in derivation of ECC public key
  tMKxC2XSecPair384 RVij;
  /// Public key of Pseudonym CA used in derivation of the ECC public key
  tMKxC2XSecPair384 Spca;
}__attribute__((__packed__)) tMKxC2XSecREPK384;

/**
 * C2X security response message
 * +-----+-----+-----+-----+---...---+
 * | USN | CID | EC  | LR  | Payload |
 * +-----+-----+-----+-----+---...---+
 *    2     2     2     2    'LR - 8'
 *
 * When ErrorCode indicates no error the Payload is a variable size (calculated
 * by 'LR - 8'), otherwise the Payload is empty (and 'LR == 8').
 *
 */

/// C2X Security command response header
typedef struct MKxC2XSecRspHdr
{
  /// Value used to identify this response and its command
  tMKxC2XSecUSN USN;
  /// C2XSec command instruction that generated this response
  tMKxC2XSecInst INS;
  /// The error code generated by the command
  tMKxC2XSecErrorCode ErrorCode;
  /// The length of the security response including the header
  uint16_t LenRsp;
  /// The payload of the response
  uint8_t Data[];
}__attribute__((__packed__)) tMKxC2XSecRspHdr;

/// Result of Verify Signature of Hash command
typedef struct MKxC2XSecVerifyRsp
{
  /// The result of the verification
  tMKxC2XSecVerRes VerResult;
}__attribute__((__packed__)) tMKxC2XSecVerifyRsp;

/// Result of Decompress and Verify Signature of Hash 256 bit command
typedef struct MKxC2XSecVerifyPK256Rsp
{
  /// The result of the verification
  tMKxC2XSecVerRes VerResult;
  /// Public Key response
  tMKxC2XSecPair256 PubKey;
}__attribute__((__packed__)) tMKxC2XSecVerifyPK256Rsp;

/// Result of Decompress and Verify Signature of Hash 384 bit command
typedef struct MKxC2XSecVerifyPK384Rsp
{
  /// The result of the verification
  tMKxC2XSecVerRes VerResult;
  /// Public Key response
  tMKxC2XSecPair384 PubKey;
}__attribute__((__packed__)) tMKxC2XSecVerifyPK384Rsp;

/// Public Key 256 bit response structure
typedef struct MKxC2XSecPubKey256Rsp
{
  /// Public Key response
  tMKxC2XSecPair256 PubKey;
}__attribute__((__packed__)) tMKxC2XSecPubKey256Rsp;

/// Public Key 384 bit response structure
typedef struct MKxC2XSecPubKey384Rsp
{
  /// Public Key response
  tMKxC2XSecPair384 PubKey;
}__attribute__((__packed__)) tMKxC2XSecPubKey384Rsp;

/**
 * C2X security message
 */
typedef union MKXC2XSecAPDU
{
  /// Command APDU
  tMKxC2XSecCmdHdr C;
  /// Response APDU
  tMKxC2XSecRspHdr R;
} __attribute__((__packed__)) tMKxC2XSecAPDU;

/**
 * C2X security request/indication
 */
typedef struct MKxC2XSec
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// C2X Security API APDU
  tMKxC2XSecAPDU APDU;
} __attribute__((__packed__)) tMKxC2XSec;

/**
 * C2X Length Definitions
 */

/// LC value for Verify Signature of Hash security message with 256 bit curve
#define MKXC2XSEC_CMD_VSOH256_LC (168U)
/// LC value for Verify Signature of Hash security message with 384 bit curve
#define MKXC2XSEC_CMD_VSOH384_LC (248U)

/// LC value for Decompress Public Key and Verify Signature of Hash security
/// message with 256 bit curve
#define MKXC2XSEC_CMD_DPKVSOH256_LC (140U)
/// LC value for Decompress Public Key and Verify Signature of Hash security
/// message with 384 bit curve
#define MKXC2XSEC_CMD_DPKVSOH384_LC (204U)

/// LC value for Decompress Public Key security message with 256 bit curve
#define MKXC2XSEC_CMD_DPK256_LC (44U)
/// LC value for Decompress Public Key security message with 384 bit curve
#define MKXC2XSEC_CMD_DPK384_LC (60U)

/// LC value for Reconstruct ECC Public Key security message with 256 bit curve
#define MKXC2XSEC_CMD_REPK256_LC (168U)
/// LC value for Reconstruct ECC Public Key security message with 384 bit curve
#define MKXC2XSEC_CMD_REPK384_LC (248U)

/// LR value for Verify Signature of Hash security response
#define MKXC2XSEC_RSP_VER_LR (12U)

/// LR value for Public Key security response message with 256 bit curve
#define MKXC2XSEC_RSP_PK256_LR (72U)
/// LR value for Public Key security response message with 384 bit curve
#define MKXC2XSEC_RSP_PK384_LR (104U)

/// LR value for Verify Signature of Hash and Decompressed Public Key security
/// response message with 256 bit curve
#define MKXC2XSEC_RSP_VERPK256_LR (76U)
/// LR value for Verify Signature of Hash and Decompressed Public Key security
/// response message with 384 bit curve
#define MKXC2XSEC_RSP_VERPK384_LR (108U)

/// AuxADCIndex enum, used to access the ADC measurements contained in the
/// Values[] array.
/// INDEX INPUT SAF5100(nominal settings)       SAF5400
///   0   VIN0  EXT_PD - Input pin              Invalid
///   1   VIN1  RG5G_1_PDET - Ant1 Power det    Valid
///   2   VIN2  RF5G_2_PDET - Ant1 Power det    Valid
///   3   VIN3  5V0_EXT2 5V*10k/57.5k = 0.87V   Valid
///   4   VIN4  5V0_EXT15V*10k/57.5k = 0.87V    Valid
///   5   VIN5  Internal TEF5100 R cal          Internal DIE Temperature
///   6   VIN6  Internal TEF5100 Temp Sensor    Invalid
typedef enum {
  /// Auxillary ADC input VIN0 (SAF5100 only)
  AUXADC_INDEX_VIN0        = 0U,
  /// Auxillary ADC input VIN1
  AUXADC_INDEX_VIN1        = 1U,
  /// Auxillary ADC input VIN2
  AUXADC_INDEX_VIN2        = 2U,
  /// Auxillary ADC input VIN3
  AUXADC_INDEX_VIN3        = 3U,
  /// Auxillary ADC input VIN4
  AUXADC_INDEX_VIN4        = 4U,
  /// Auxillary ADC input RCAL (SAF5100)
  /// Internal DIE Temperature (SAF5400)
  /// TEMPERATURE  = ADCVALUE(SIGNED)*0.0235625 - 284.6  (+-5C)
  AUXADC_INDEX_VIN5        = 5U,
  /// Auxillary ADC input internal temperature sensor (SAF5100 only)
  AUXADC_INDEX_VIN6        = 6U,
  /// Number of inputs to the Aux ADC for SAF5100
  AUXADC_INDEX_COUNT       = 7U,
  /// Invalid ADC input (used for disabling Tx power det input) (SAF5100 only)
  AUXADC_INVALID           = 8U,
  /// ADC Bitmask (Limit number of bits to number of ADCs) for SAF5100
  AUXADC_BITMASK_SAF5100   = ((1U << AUXADC_INDEX_COUNT)-1U),
  /// ADC Bitmask (Limit number of bits to number of ADCs) for SAF5400
  AUXADC_BITMASK_SAF5400   = 0x03EU
} eMKxAuxADCIndex;
/// @copydoc eMKxAuxADCIndex
typedef uint8_t tMKxAuxADCIndex;

/**
 * Calibration Data
 * The following section contains all of the calibration data and various
 * configuration data structures which result in a single calibration config
 * message MKXIF_CALIBRATION being used to configure the fixed portion of the
 * radio's configuration.  This data applies to both radios.
 */

/// MKx Antenna mode selection for individual antenna port
typedef enum MKxCompensatorSel {
  /// No external compensator connected to antenna port
  MKX_ANT_MODE_NO_COMPENSATOR = 0,
  /// Antenna port connected to compensator (enables compensator UART operation)
  MKX_ANT_MODE_COMPENSATOR = 1
} eMKxCompensatorSel;
/// @copydoc eMKxCompensatorSel
typedef uint8_t tMKxCompensatorSel;

/// MKx power calibration mode selection
typedef enum MKxPowerCalMode {
  /// No tx power calibration applied - Note Tx power detector measurement will
  /// still be reported via AuxADC API
  MKX_POWER_CAL_OFF           = 0,
  /// Use only the temperature for tx power calibration - Note Tx power
  /// detector measurement still be reported via AuxADC API
  MKX_POWER_CAL_TEMP_ONLY     = 1,
  /// Use the tx power detector for calibration.  Note this mode uses
  /// temperature based power calibration until 1st valid TxPowerDet read.
  /// This option applies to with and without the compensator.
  MKX_POWER_CAL_POWERDET      = 2,
} eMKxPowerCalMode;
/// @copydoc eMKxPowerCalMode
typedef uint8_t tMKxPowerCalMode;

/// Compensator UART return input source.
/// Note AuxADC should only be used when using local PA and UART should only be
/// used when using a compensator.
typedef enum MKxCompensatorReturn {
  /// Compensator return signal on UART0
  COMPENSATOR_UART0 = 0U,
  /// Compensator return signal on UART1
  COMPENSATOR_UART1 = 1U,
  /// Compensator return signal on UART2
  COMPENSATOR_UART2 = 2U,
  /// Compensator return signal on UART3
  COMPENSATOR_UART3 = 3U,
} eMKxCompensatorReturn;
/// @copydoc eMKxCompensatorReturn
typedef uint32_t tMKxCompensatorReturn;

/// MKx RSSI calibration operating mode
typedef enum MKxRSSICalMode {
  /// No compensation
  MKX_RSSI_CAL_OFF = 0,
  /// RSSI compensation enabled
  MKX_RSSI_CAL_ON = 1,
} eMKxRSSICalMode;
/// @copydoc eMKxRSSICalMode
typedef uint8_t tMKxRSSICalMode;

/**
 * Temperature compensation calibration data
 * Data structure provides linear based compensation parameters
 * - Compensation = ZeroIntercept[ChanIndex] + Slope*CurrentTemperature
 *
 * where ChanIndex range is 0..CAL_CHANNEL_COUNT-1
 * Values correspond to the following channels:
 * 0:168, 1:170, 2:172, 3:174, 4:176, 5:178, 6:180, 7:182, 8:184
 * 9:All Other Channels
 *
 * The S15Q16 fixed point format (used for both Slope and ZeroIntercept
 * parameters) scales the values such that 1.0 = 2^16 = 65536.
 *
 * Used for RSSI calibration across temperature
 * - RSSIAdjust = ZeroIntercept[ChanIndex] + Slope*CurrentTemperature (in dB)
 * - ReportedRSSI = MeasuredRSSI + RSSIAdjust (in dB)
 *
 * Used for temperature based Tx power calibration
 * - TxPowerAdjust = ZeroIntercept[ChanIndex] + Slope*CurrentTemperature (in dB)
 * - TxPower = RequestedTxPower + TxPowerAdjust (in dB)
 */
typedef struct MKxTemperatureComp
{
  /// Slope for temperature compensation (in dB/degC, S15Q16 format)
  int32_t Slope;
  /// Frequency dependent zero temperature intercept (in dB, S15Q16 format)
  int32_t ZeroIntercept[CAL_CHANNEL_COUNT];
}__attribute__((__packed__)) tMKxTemperatureComp;

/**
 * Data structure that defines a calibration point and line in the Tx power
 * detector value vs actual transmit power relationship.
 * The rate parameter is in dBm per PowerDetValue
 */
typedef struct MKxPowerDetCalPoint
{
  /// Power detector calibration point, power detector value
  int32_t PowerDet;
  /// Power detector calibration point, power in dBm value (S15Q16 format)
  int32_t PowerConstant;
  /// Power detector calibration rate dBm/PowerDet from defined point (S15Q16)
  int32_t PowerRate;
} __attribute__((__packed__)) tMKxPowerDetCalPoint;

/**
 * Data structure that defines a temperature offset adjustment line in the Tx
 * power offset vs temperature relationship.
 * The rate parameter is in dBm per degree Celsius.
 */
typedef struct MKxPowerDetTempCalPoint
{
  /// Power detector calibration temperature
  /// Temperature where the power detector curves have been calculated at
  int32_t CalTemp;
  /// Power offset rate dBm/deg C (S15Q16)
  int32_t TempOffsetRate;
} __attribute__((__packed__)) tMKxPowerDetTempCalPoint;

/**
 * Local PA Power detector calibration data
 * Used to configure the tx power detector calibration by specifying the
 * TxPowerDet relationship to actual/measured power.  Specification is in the
 * form of two lines (each line specified as a single point and a rate).
 * All TxPowerDet values below the 1st calibration point are ignored.
 */
typedef struct MKxPowerDetCal
{
  /// Power detector calibration point/line.  Index 0 is the first Cal point
  tMKxPowerDetCalPoint CalPoint[CAL_POINT_COUNT];
  /// Power detector temperature calibration point/line
  tMKxPowerDetTempCalPoint TempCalPoint;
} __attribute__((__packed__)) tMKxPowerDetCal;

/**
 * Auto-regression parameters
 * FilteredValue = Alpha*NewValue + Beta*PrevFilteredValue
 * The 8Q8 fixed point format scales the values such that
 * 1.0 = 2^8 = 256
 * Alpha + Beta must add to 1.0
 */
typedef struct MKxAutoReg
{
  /// Auto-regression alpha value in 8Q8 format
  uint16_t Alpha;
  /// Auto-regression alpha value in 8Q8 format
  uint16_t Beta;
} __attribute__((__packed__)) tMKxAutoReg;

/**
 * Compensator specific configuration and calibration data
 * Contains all of the settings for the compensator for a single antenna
 *
 * The Tx PA on delay corresponds to the time between PA On and the modulated
 * signal output, with compensator.  Note when transmitting on both antennas,
 * the TxPAOnDelay for Ant1 is used and TxPAOnDelay for Ant2 is ignored.
 *
 * The CableLoss parameter is used for both Tx power calibration (combined
 * with TxRFGain) and RSSI measurements (combined with RxRFGain).
 *
 * See the CWD-P0115-MK5-USRM-WW01-318-MK5_Calibration_App_Note.doc for further
 * information on how these parameters are used.
 */
typedef struct MKxCompensatorConfig
{
  /// Tx PA on additional delay (in 300 MHz timer ticks), when using compensator
  /// (currently unused)
  uint32_t TxPAOnDelay;
  /// Selects debug mode which enables Tx power calibration parameter reporting
  /// (currently unused)
  uint32_t DebugEnable;
  /// Selects the compensator return UART input signal
  tMKxCompensatorReturn CompensatorReturn;
  /// Threshold indicating when measured compensator Tx power valid (dBm S23Q8)
  int32_t TxPowerThresh;
  /// Auto-regression parameters for the compensator Tx power measurements
  tMKxAutoReg AutoReg;
  /// Tx gain of the RF circuitry external to the TEF5x00 (in dB S23Q8 format)
  /// This is subtracted from the requested Tx powers
  int32_t TxRFGain;
  /// Cable loss of cable between TEF5x00 and compensator, in S23Q8 dB
  int32_t CableLoss;
  /// Rx Gain of the compensator in S23Q8 dB
  int32_t RxRFGain;
  /// RSSI calibration config data for compensator LNA
  tMKxTemperatureComp RSSICal;
} __attribute__((__packed__)) tMKxCompensatorConfig;

/**
 * Local PA/LNA configuration and calibration data
 * Contains all of the settings applicable to when using a local PA/LNA for a
 * single antenna.
 *
 * The Tx PA on delay corresponds to the time between PA On and the modulated
 * signal output.  Note when transmitting on both antennas, the TxPAOnDelay for
 * Ant1 is used and TxPAOnDelay for Ant2 is ignored.
 *
 * See the CWD-P0115-MK5-USRM-WW01-318-MK5_Calibration_App_Note.doc for further
 * information on how these parameters are used.
 */
typedef struct MKxLocalPALNAConfig
{
  /// Tx PA on additional delay (in 300 MHz timer ticks), when using local PA
  /// (currently unused)
  uint32_t TxPAOnDelay;
  /// Selects the input signal for the Local PA Tx Power detector input
  tMKxAuxADCIndex TxPowerDetInput;
  /// Selects debug mode which enables Tx power calibration parameter reporting
  /// (currently unused)
  uint8_t DebugEnable;
  /// Alignment to 32 bits
  uint8_t Reserved[2];
  /// Power detector based Tx power calibration data for the antenna
  tMKxPowerDetCal TxPowerDetCal;
  /// Temperature based Tx power calibration data for the antenna
  tMKxTemperatureComp TxPowerTempCal;
  /// Auto-regression parameters for the Tx power calibration correction
  /// (used for either power detector based or temperature based calibration)
  tMKxAutoReg AutoReg;
  /// Tx gain of the RF circuitry external to the TEF5x00 (in dB S23Q8 format)
  /// This is compared to an internal reference RF gain and the difference is
  /// subtracted from the requested Tx powers
  int32_t TxRFGain;
  /// RSSI calibration config data for local LNA.  Note this calibration is also
  /// used when using a compensator, as a local LNA is also present.
  tMKxTemperatureComp RSSICal;
} __attribute__((__packed__)) tMKxLocalPALNAConfig;

/**
 * Per Antenna Calibration data
 * Data structure contains all of the top-level configuration selections for
 * the antenna port, regarding transmit power calibration modes, power limits,
 * and also RSSI calibration selection.
 *
 * The power limit parameters are used limit the temperature compensated TxPower
 * when the measured temperature > PowerLimitMaxTemp.
 * The Tx extra drive power offset is used to add or subtract extra transmit
 * power which is added to the requested transmit power and can be considered
 * outside the scope of the operation of the Tx power calibration.
 */
typedef struct MKxAntCalibration
{
  /// Select between compensator and local PA/LNA only
  tMKxCompensatorSel CompensatorSel;
  /// Selects the Tx power calibration mode (Off, Temperature or TxPowerDet)
  tMKxPowerCalMode TxPowerCalMode;
  /// RSSI calibration operating mode
  tMKxRSSICalMode RSSICalMode;
  /// Alignment to 32 bits
  uint8_t Reserved;
  /// Compensator specific configuration and calibration data
  tMKxCompensatorConfig CompensatorConfig;
  /// Local PA/LNA specific configuration and calibration data
  tMKxLocalPALNAConfig LocalPALNAConfig;
  /// Extra power offset that is added to txpower regardless of power
  /// calibration scheme (in dB S23Q8 format). Used to alter the per-board tx
  /// power offset, across the range of supported frequency channels
  int32_t TxPowerExtraDrive[CAL_CHANNEL_COUNT];
  /// Maximum temp (degC) for when tx power is limited to PowerLimitMaxPower
  int16_t TxPowerLimitMaxTemp;
  /// Set maximum power (in 0.5 dBm units) when maximum temperature is reached
  tMKxPower TxPowerLimitMaxPower;
  /// Tx LO leakage and IQ imbalance calibration start search frequency (MHz)
  /// Set to -1 for algorithm to scan for optimal frequency.
  /// Set >0 to set the frequency in MHz e.g. 5900
  int32_t TxLOSearchFreq;
} __attribute__((__packed__)) tMKxAntCalibration;

/**
 * Acquisition config
 * Used to set the acquisition parameters for single and dual antenna operation.
 * Note SAF5400 does not use the RxAcqDetectThreshDualAnt parameter.  It uses
 * both RxAcqDetectThreshSingAnt1 and RxAcqDetectThreshSingAnt2 separately when
 * configured for dual antenna operation.
 */
typedef struct MKxAcquisitionConfig
{
  /// Coarse Acquisition Detection Threshold for Ant1 single antenna operation
  uint32_t RxAcqDetectThreshSingAnt1;
  /// Coarse Acquisition Detection Threshold for Ant2 single antenna operation
  uint32_t RxAcqDetectThreshSingAnt2;
  /// Coarse Acquisition Detection Threshold for dual antenna operation.
  /// SAF5100 only (Unused for SAF5400)
  uint32_t RxAcqDetectThreshDualAnt;
} __attribute__((__packed__)) tMKxAcquisitionConfig;

/// MKx temperature sensor source
typedef enum MKxTempSource {
  /// No I2C sensors present, temperatures set via the MKXIF_TEMP command
  MKX_TEMP_SOURCE_MANUAL = 0,
  /// Single I2C sensor, acting for both PAAnt1 and PAAnt2 temperature settings
  MKX_TEMP_SOURCE_I2C_SINGLE = 1,
  /// Dual I2C sensors, one for each PA (PAAnt1, PAAnt2)
  MKX_TEMP_SOURCE_I2C_DUAL = 2,
  /// Single AuxADC analog temperature sensor, acting for both PAAnt1 & PAAnt2
  MKX_TEMP_SOURCE_ANALOG_SINGLE = 3,
  /// Dual AuxADC analog temperature sensors, one for each PA (PAAnt1, PAAnt2)
  MKX_TEMP_SOURCE_ANALOG_DUAL = 4,
} eMKxTempSource;
/// @copydoc eMKxTempSource
typedef uint16_t tMKxTempSource;

/**
 * Temperature Config
 * Used to configure the temperature sensing
 * For temperature sensing configuration, SensorSource =
 *   MKX_TEMP_SOURCE_MANUAL, temperatures set via the MKXIF_TEMP message
 *   MKX_TEMP_SOURCE_I2C_SINGLE, temperatures set via single I2C temp sensor
 *                             (connected to I2CAddrSensor1)
 *   MKX_TEMP_SOURCE_I2C_DUAL, temperatures set via dual I2C temp sensors
 * Note
 * I2CAddrSensor1 value is don't care when SensorSource = MKX_TEMP_SOURCE_MANUAL
 * I2CAddrSensor2 value is don't care when SensorSource = MKX_TEMP_SOURCE_MANUAL
 * or MKX_TEMP_SOURCE_I2C_SINGLE
 */
typedef struct MKxTempConfig
{
  /// Source of the temperature sensor/s connected to the SAF5x00
  tMKxTempSource SensorSource;
  /// I2C Address for the first I2C temperature sensor.
  uint8_t I2CAddrSensor1;
  /// I2C Address for the second I2C temperature sensor.  Ignored when
  /// SensorSource = MKX_TEMP_SOURCE_I2C_SINGLE
  uint8_t I2CAddrSensor2;
  /// Number of 4MHz cycles between each I2C temp sensor read stage
  /// (2 stages per individual sensor read)
  uint32_t SensorPeriod;
} __attribute__((__packed__)) tMKxTempConfig;

/**
 * GPIO pin configurations for RF functions
 * Custom pin config only supported by SAF5400
 * Pins can be 0-15, with 16 indicating disabled.  Each value corresponds to the
 * GPIO3 pin index assignment, e.g. 0 = GPIO3_0.
 */
typedef struct MKxRFPinConfig
{
  /// GPIO pin selection for PAEnable signal
  uint16_t PAEnableGPIO;
  /// GPIO pin selection for LNAEnable signal
  uint16_t LNAEnableGPIO;
  /// GPIO pin selection for RemotePAEnable signal
  uint16_t RemotePAEnableGPIO;
  /// GPIO pin selection for FEM C1 signal
  uint16_t C1GPIO;
  /// GPIO pin selection for Tx Claim signal
  uint16_t TxClaimGPIO;
  /// GPIO pin selection for Compensator Enable signal
  uint16_t CompensatorEnableGPIO;
} __attribute__((__packed__)) tMKxRFPinConfig;

/**
 * GPIO pin RF timing configurations.
 * Refer the documention and timing diagrams for more detail on how these
 * relate to real world behaviours
 * Custom pin config only supported by SAF5400
 */
typedef struct MKxRFTimingConfig
{
  /// Time between remotePaEnable to local frontend control (in 160MHz ticks)
  uint16_t PAEnableLNADisable;
  /// Time the PA Enable is asserted before baseband is output (in 160MHz ticks)
  uint16_t BasebandStart;
  /// Delay in triggering an AD conversion after tx start (in 160MHz ticks)
  uint16_t AuxillaryADC;
  /// Time after a BB tx is finished, before deasserting remote PAEnable (ticks)
  uint16_t RemotePADisable;
  /// Time after end of signal, before deasserting PAEnable (in 160MHz ticks)
  uint16_t PADisable;
  /// Time after PA is disabled, before LNA is enabled (in 160MHz ticks)
  uint16_t LNAEnable;
} __attribute__((__packed__)) tMKxRFTimingConfig;

/**
 * GPIO pin configurations for the coexistence signals (SAF5400 only),
 * used for when operating two SAF5400s.
 * Pins can be 0-15, with 16 indicating disabled.  Each value corresponds to the
 * GPIO3 pin index assignment, e.g. 0 = GPIO3_0.
 */
typedef struct MKxCoexistPinConfig
{
  /// Pin index for output coexistence signal, indicating radio is transmitting
  uint16_t TxActiveGPIO;
  /// Pin index for output coexistence signal, indicating radio is receiving
  uint16_t RxActiveGPIO;
  /// Pin index for input coexistence signal (other radio is transmitting)
  uint16_t OtherRadioTxActiveGPIO;
  /// Pin index for input coexistence signal (other radio is receiving)
  uint16_t OtherRadioRxActiveGPIO;
} __attribute__((__packed__)) tMKxCoexistPinConfig;

/**
 * GPIO pin configurations for the device
 * Pins can be 0-15, with 16 indicating disabled
 * Custom pin config only supported by SAF5400
 */
typedef struct MKxPinConfig
{
  // RF pin configuration for each antenna
  tMKxRFPinConfig RF[MKX_ANT_COUNT];
  // RF pin timing configuration for 5G9Hz
  tMKxRFTimingConfig Timing;
  // Pin for 1PPS input signal
  uint16_t OnePPSGPIO;
  /// Pin selection for the Clear Channel Assessment (CCA) debug signal
  uint16_t CCAGPIO;
  /// Pin configurations for Dual SAF5400 coexistence
  tMKxCoexistPinConfig Coexistence;
} __attribute__((__packed__)) tMKxPinConfig;


/**
 * Data structure that defines a calibration point and line used to convert an
 * ADC value to degrees C.
 * if AuxADCMeasure >= AuxADCVal
 *   Temperature = (AuxADCMeasure * TempRate) + TempOffset
 */
typedef struct MKxAuxADCCalPoint
{
  /// Minimum AuxADC value for which the temp conversion line settings apply
  int32_t AuxADCVal;
  /// Temperature calibration rate in C/AuxADC (S15Q16)
  int32_t TempRate;
  /// Temperature calibration offset in degrees C (S15Q16 format)
  int32_t TempOffset;
} __attribute__((__packed__)) tMKxAuxADCCalPoint;

/**
 * Calibration data for an Analog temperature sensor (SAF5400 Only)
 * Temperature conversion from AuxADC measurement uses the following
 * if AuxADCMeasure >= CalPoint[1].AuxADCVal
 *   Temperature = (AuxADCMeasure*CalPoint[1].TempRate) + CalPoint[1].TempOffset
 * else if AuxADCMeasure >= CalPoint[0].AuxADCVal
 *   Temperature = (AuxADCMeasure*CalPoint[0].TempRate) + CalPoint[0].TempOffset
 */
typedef struct MKxAnalogTempCalib
{
  // The AuxADC input pin for the analog temperature sensor
  tMKxAuxADCIndex AuxADCInput;
  // 32 bit alignment
  uint8_t Pad[3];
  // A two line fit to convert raw ADC values to degrees C
  tMKxAuxADCCalPoint CalPoint[CAL_POINT_COUNT];
} __attribute__((__packed__)) tMKxAnalogTempCalib;

/**
 * The configuration required to enable the analog temperature sensors
 * (SAF5400 Only)
 * Note when SensorSource == MKX_TEMP_SOURCE_I2C_SINGLE, only
 * Antenna[ANT1_INDEX].AuxADCInput is used (i.e. Antenna[ANT2_INDEX].AuxADCInput
 * is ignored).
 */
typedef struct MKxAnalogTempConfig
{
  // The analog temperature sensor calibration per antenna
  tMKxAnalogTempCalib Sensor[MKX_ANT_COUNT];
} __attribute__((__packed__)) tMKxAnalogTempConfig;

/**
 * Calibration configuration data
 * Grouping of the per antenna calibration data, the acquisition config and the
 * temperature config.  Note this data structure applies to both radios.
 * It is important to not send calibration data during transmission periods
 * given the calibration data is not double buffered and as such the a partial
 * update may temporarily be used for a transmission.
 */
typedef struct MKxCalibrationData
{
  /// Version of the calibration data structure
  uint32_t Version;
  /// Grouping of per antenna calibration parameters
  tMKxAntCalibration AntCalibration[MKX_ANT_COUNT];
  /// Acquisition Config Data for 10 MHz bandwidth operation
  tMKxAcquisitionConfig AcquisitionConfig;
  /// Temperature Config Data
  tMKxTempConfig TempConfig;
  /// Acquisition Config Data for 20 MHz bandwidth operation
  tMKxAcquisitionConfig AcquisitionConfig20MHz;
  /// Pin Configurations for GPIO3
  /// Custom pin config only supported by SAF5400
  tMKxPinConfig PinConfig;
  /// Analogue Temperature Sensor Calibration
  tMKxAnalogTempConfig AnalogTempConfig;
} __attribute__((__packed__)) tMKxCalibrationData;

/**
 * Calibration configuration message
 */
typedef struct MKxCalibration
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// Calibration Configuration data
  tMKxCalibrationData CalibrationData;
} __attribute__((__packed__)) tMKxCalibration;

/**
 * Temperature measurement data
 */
typedef struct MKxTempData
{
  /// Temperature setting in degrees C for PA Ant1, when no I2C sensors present
  int16_t TempPAAnt1;
  /// Temperature setting in degrees C for PA Ant2, when no I2C sensors present
  int16_t TempPAAnt2;
} __attribute__((__packed__)) tMKxTempData;

/**
 * Temperature measurement message
 * Used to indicate (or manually set) the two temperatures used for tx power
 * compensation.  Data structure corresponds to MKXIF_TEMP message type.
 * @note This message is only accepted by the SAF5x00 when SensorSource in
 * MKxTempConfig is set to MKX_TEMP_SOURCE_MANUAL.
 */
typedef struct MKxTemp
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// Temperature measurement data
  tMKxTempData TempData;
} __attribute__((__packed__)) tMKxTemp;

/**
 * Auxiliary ADC Data and Configuration Messages
 * Used to receive measured data from the auxiliary ADCs and to set / read the
 * current configuration
 *
 * The ConfigRegister contains bit-fields that are used to enable and disable
 * which ADCs are included in the round-robin measurements.
 * Bit  Aux Input  SAF5100  SAF5400
 *  0   Vin0       -        Unused
 *  1   Vin1       PA Ant1  -
 *  2   Vin2       PA Ant2  -
 *  3   Vin3       -        -
 *  4   Vin4       -        -
 *  5   Vin5       Rcal     Temp
 *  6   Vin6       Temp     Unused
 * The measurement message contains an array of measurements and a timestamp of
 * the last completed round-robin. The array can be accessed via the
 * eMKxAuxADCIndex enum.
 */

/**
 * Auxiliary ADC measurement data
 */
typedef struct MKxAuxADCData
{
  /// Measured values from ADC
  uint32_t Values[AUXADC_INDEX_COUNT];
  /// Timestamps of last completed measurement
  tMKxTSF Timestamps[AUXADC_INDEX_COUNT];
} __attribute__((__packed__)) tMKxAuxADCData;

/**
 * Auxiliary ADC measurement message
 */
typedef struct MKxAuxADC
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// Auxiliary ADC measurement data
  tMKxAuxADCData AuxADCData;
} __attribute__((__packed__)) tMKxAuxADC;

/**
 * Auxiliary ADC configuration data
 */
typedef struct MKxAuxADCConfigData
{
  /// Configuration Register of ADC
  uint32_t ConfigRegister;
} __attribute__((__packed__)) tMKxAuxADCConfigData;

/**
 * Auxiliary ADC configuration message
 */
typedef struct MKxAuxADCConfig
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// Auxiliary ADC measurement data
  tMKxAuxADCConfigData AuxADCConfigData;
} __attribute__((__packed__)) tMKxAuxADCConfig;

/**
 * Log message type
 */
typedef enum MKxLogType
{
  /// Error log
  MKX_LOG_ERROR   = 0U,
  /// Warning log
  MKX_LOG_WARNING = 2U,
  /// Info log - parameters are interpreted as hexadecimal values
  MKX_LOG_INFO    = 4U,
  /// Enable sending log messages to the host
  MKX_LOG_ENABLE  = 64U,
  /// Disable sending log messages to the host
  MKX_LOG_DISABLE = 128U,
} eMKxLogType;
/// @copydoc eMKxLogType
typedef uint32_t tMKxLogType;

/**
 * MKx Log format
 */
typedef struct MKxLog
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  /// Log type (see @ref eMKxLogType)
  tMKxLogType LogType;
  /// Optional log text
  uint8_t Text[MAX_LOG_TEXT_BYTES];
  /// Number of parameters
  uint32_t NumParameters;
  /// Array of optional parameters
  int32_t Parameters[MAX_NUM_LOG_PARAMETERS];
} __attribute__((__packed__)) tMKxLog;

/**
 * MKx GPIO Commands
 * Reference MKxGPIOData for more information
 */
typedef enum
{
  /// Configure a GPIO pin
  GPIO_CONFIG    = 0U,
  /// Set the output of a GPIO pin
  GPIO_SET       = 1U,
  /// Read from a GPIO pin.
  GPIO_READ      = 2U,
  /// Determine if pin is already assigned
  GPIO_STATUS    = 3U
} eMKxGPIOCmd;
/// @copydoc eMKxGPIOCmd
typedef uint16_t tMKxGPIOCmd;

/**
 * The data message for controlling GPIOs on the SAF5400
 *
 * Commands:
 * GPIO_CONFIG - Set a pin In/Out config.  Value: Input (0) / Output (1)
 * GPIO_SET    - Set a pin output state.   Value: Low (0) / High (1)
 * GPIO_READ   - Read a pin's value.       Value: Low (0) / High (1)
 * GPIO_STATUS - Determine if pin in use   Value: Available (0) / Assigned (1)
 *
 * Example Commands:
 * Set GPIO3_12 to Output
 * {Cmd = GPIO_CONFIG, Pin = 12, Value = 1}
 * Set GPIO3_12 to HIGH
 * {Cmd = GPIO_SET, Pin = 12, Value = 1}
 * Set GPIO3_12 to LOW
 * {Cmd = GPIO_SET, Pin = 12, Value = 0}
 *
 * Command to read GPIO3_8
 * {Cmd = GPIO_READ, Pin = 8, Value = n/a}
 * Radio will then respond with a GPIO message containing
 * {Cmd = GPIO_READ, Pin = 8, Value = 0/1 (Low/High)}
 */

typedef struct MKxGPIOData
{
  /// The command to send to the radio
  tMKxGPIOCmd Cmd;
  /// Pin index matching the SAF5x00 IC GPIO3 pin assignments
  uint16_t PinNumber;
  /// Value related to the GPIO command. For either input or output.
  uint32_t Value;
} __attribute__((__packed__)) tMKxGPIOData;

/**
 * MKx GPIO message format
 */
typedef struct MKxGPIO
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// GPIO Message Data
  tMKxGPIOData GPIOData;
} __attribute__((__packed__)) tMKxGPIO;

/**
 * LLC API version data structure
 */
typedef struct MKxAPIVersionData
{
  /// Major version number.  Mismatch results in blocked communications
  uint16_t Major;
  /// Minor version number.  Mismatch results in warning
  uint16_t Minor;
} __attribute__((__packed__)) tMKxAPIVersionData;

/**
 * MKx LLC API Version message
 */
typedef struct MKxAPIVersion
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  /// LLC API version data
  tMKxAPIVersionData VersionData;
} __attribute__((__packed__)) tMKxAPIVersion;

/**
 * MKx Loopback data structure
 */
typedef struct MKxLoopbackData
{
  /// Timestamp seconds (not altered by SAF5x00)
  uint32_t TimestampSec;
  /// Timestamp microseconds (not altered by SAF5x00)
  uint32_t TimestampMicrosec;
  /// Message data
  uint8_t Data[];
} __attribute__((__packed__)) tMKxLoopbackData;

/**
 * MKx Loopback message
 */
typedef struct MKxLoopback
{
  /// Interface Message Header
  tMKxIFMsg Hdr;
  // Loopback data
  tMKxLoopbackData LoopbackData;
} __attribute__((__packed__)) tMKxLoopback;

/**
 * MKx Fault Commands
 * Reference MKxFaultData for more information
 */
typedef enum
{
  /// Get state information
  MKX_FAULT_STATE     = 0U,
  /// Set a fault
  MKX_FAULT_SET       = 1U,
  /// Clear the fault state
  MKX_FAULT_CLEAR     = 2U,
} eMKxFaultCmd;
/// @copydoc eMKxFaultCmd
typedef uint16_t tMKxFaultCmd;

/**
 * MKx Fault message data structure
 * This message is used to either set a fault on the SAF5x00 for test purposes,
 * clear the fault (which clears the fail-safe state and re-enables the fault
 * checking) or to obtain fault state information.
 * When clearing, it is possible to clear a test fault command specifically
 * by setting the CommandErrorCode to the exact test fault code.
 */
typedef struct MKxFaultData
{
  /// The command to send to the radio
  tMKxFaultCmd Cmd;
  /// The fault to set to if Cmd == MKX_FAULT_SET, see @ref eSAFErrorCode
  /// Clearing of test fault, if Cmd == MKX_FAULT_CLEAR and
  /// CommandErrorCode == SAF_ERROR_ARM_FAULT_TEST or SAF_ERROR_DSP_FAULT_TEST
  int16_t CommandErrorCode;
  /// Indication of whether the radio is in fail safe state or not
  uint32_t FailSafeState;
  /// Count of the number of faults detected by the SAF5x00
  uint32_t FaultCount;
  /// Error code of the last fault, see @ref eErrorCode
  int32_t FaultErrorCode;
} __attribute__((__packed__)) tMKxFaultData;

/**
 * MKx Fault message format
 */
typedef struct MKxFault
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// Fault Message Data
  tMKxFaultData FaultData;
} __attribute__((__packed__)) tMKxFault;

/**
 * MKx Reset message format (SAF5400 only)
 * This message is a command to perform a warm reset on the SAF5300/SAF5400 IC.
 * The reserved field is required to ensure the message is >= 13 bytes for
 * network interface conformance.
 */
typedef struct MKxReset
{
  /// Interface Message Header (reserved area for LLC usage)
  tMKxIFMsg Hdr;
  /// Reserved
  uint32_t Reserved;
} __attribute__((__packed__)) tMKxReset;

/// LLC interface structures and functions are not required by the SAF
#ifndef __TARGET_SAF__

#ifndef DISABLE_MISRA
#ifdef __COVERITY__
#define DISABLE_MISRA(x) _Pragma(x)
#else
#define DISABLE_MISRA(x)
#endif
#endif

//------------------------------------------------------------------------------
// Function Types
//------------------------------------------------------------------------------

/**
 * @brief Request the configuration of a particular radio channel
 * @param pMKx MKx handle
 * @param Radio the selected radio
 * @param pConfig Pointer to the new configuration to apply
 * @return MKXSTATUS_SUCCESS if the request was accepted
 *
 * @code
 * # Get the current/default config
 * tMKxRadioConfig Cfg = {0,};
 * memcpy(&Cfg, &(pMKx->Config.Radio[MKX_RADIO_A]), sizeof(Cfg));
 * # Update the values that we want to change
 * Cfg.Mode = MKX_MODE_SWITCHED
 * Cfg.Chan[MKX_CHANNEL_0].PHY.ChannelFreq = 5000 + (5 * 178)
 * Cfg.Chan[MKX_CHANNEL_1].PHY.ChannelFreq = 5000 + (5 * 182)
 * ...
 * # Apply the configuration
 * Res = MKx_Config(pMKx, MKX_RADIO_A, &Cfg);
 * @endcode
 */
typedef tMKxStatus (*fMKx_Config) (struct MKx *pMKx,
                                   tMKxRadio Radio,
                                   tMKxRadioConfig *pConfig);

/**
 * @brief Request the transmission of an 802.11 frame
 * @param pMKx MKx handle
 * @param pTxPkt The packet pointer (including tx header)
 * @param pPriv Pointer to provide when invoking the @ref fMKx_TxCnf callback
 * @return MKXSTATUS_SUCCESS if the transmit request was accepted
 *
 * @note The following MAC header parameters are manipulated by the MAC layer:
 * - Duration field is overwritten (for data frames only)
 * - Sequence number is incremented and overwritten (note MAC layer maintains
 * sequence numbers for each individual QoS queue. This is performed for all
 * frame types except for control frame types).
 * In addition, unicast frames are determined by the destination address top
 * byte LSB being set to 0.
 * - For unicast QoS frames, the ACK policy is determined by the QoSControl
 * setting.
 * - For unicast non-QoS frames, the ACK policy is always true.
 * - For multi-cast QoS frames, the ACK policy of the QoSControl field is
 * cleared by the MAC layer to be  always false
 *
 * @note When applicable, RTS, CTS, and Ack control frames are created by the
 * MAC layer and are not made available via the LLC interface.
 *
 * @note The buffer must lie in DMA accessible memory and there is usually some
 * relation between pTxPkt and pPriv. A possible stack implementation is
 * shown below:
 * @code
 * Len = <802.11 Frame length> + sizeof(struct MKxTxDescriptor);
 * pSkb = alloc_skb(Len, GFP_DMA);
 * pTxPkt = pSkb->data;
 * pTxPkt->Length = <802.11 Frame length>
 *  ...
 * Res = MKx_TxReq(pMKx, pTxPkt, pSkb);
 * @endcode
 */
typedef tMKxStatus (*fMKx_TxReq) (struct MKx *pMKx,
                                  tMKxTxPacket *pTxPkt,
                                  void *pPriv);

/**
 * @brief Transmit notification callback
 * @param pMKx MKx handle
 * @param pTxPkt As provided in the @ref fMKx_TxReq call
 * @param pTxEvent A pointer to the event data generated for the TxReq
 * @param pPriv As provided in the @ref fMKx_TxReq call
 * @return MKXSTATUS_SUCCESS if the 'confirm' was successfully handled.
 *         Other values are logged for debug purposes.
 *
 * A callback invoked by the LLC to notify the stack that the provided transmit
 * packet was either successfully transmitted or failed to be
 * queued/transmitted. The status can be determined from first inspecting
 * pTxEvent->Hdr.Ret - if this indicates success (MKXSTATUS_SUCCESS) then the
 * TxReq was successfully sent to the radio. The success / failure of the radio
 * transmitting the packet can then be observed by inspecting
 * pTxEvent->TxEventData.TxStatus. i.e.:
 *
 * @code
 * {
 *   tMKxStatus Result = (pTxEvent->Hdr.Ret == MKXSTATUS_SUCCESS ?
 *                        pTxEvent->TxEventData.TxStatus :
 *                        pTxEvent->Hdr.Ret);
 * }
 * @endcode
 *
 * @note: The pTxEvent should not be modified and will be freed after return
 * from this callback.
 *
 * Continuing the example from @ref fMKx_TxReq...
 * @code
 * {
 *   ...
 *   free_skb(pPriv);
 *   return MKXSTATUS_SUCCESS;
 * }
 * @endcode
 */
typedef tMKxStatus (*fMKx_TxCnf) (struct MKx *pMKx,
                                  tMKxTxPacket *pTxPkt,
                                  const tMKxTxEvent *pTxEvent,
                                  void *pPriv);

/**
 * @brief Flush all pending transmit packets
 * @param pMKx MKx handle
 * @param RadioID The specific radio (MKX_RADIO_A or MKX_RADIO_B)
 * @param ChannelID The specific channel (MKX_CHANNEL_0 or MKX_CHANNEL_1)
 * @param TxQueue The specific queue (MKX_TXQ_COUNT for all)
 * @return MKXSTATUS_SUCCESS if the flush request was accepted
 *
 */
typedef tMKxStatus (*fMKx_TxFlush) (struct MKx *pMKx,
                                    tMKxRadio RadioID,
                                    tMKxChannel ChannelID,
                                    tMKxTxQueue TxQueue);

/**
 * @brief Callback invoked by the LLC to allocate a receive packet buffer
 * @param pMKx MKx handle
 * @param BufLen Maximum length of the receive packet
 * @param ppBuf Pointer to a to-be-allocated buffer for the receive packet.
 *              In the case of an error: *ppBuf == NULL
 * @param ppPriv Pointer to provide when invoking any callback associated with
 *               this receive packet. Usually the provided contents of ppBuf
 *               and ppPriv have some association
 * @return MKXSTATUS_SUCCESS if the receive packet allocation request was
 *         successful. Other values may be logged by the MKx for debug purposes.
 *
 * A callback invoked by the LLC in an interrupt context to request the
 * stack to allocate a receive packet buffer.
 *
 * @note The buffer must lie in DMA accessible memory.
 * A possible implementation is shown below:
 * @code
 * *ppPriv = alloc_skb(BufLen, GFP_DMA|GFP_ATOMIC);
 * *ppBuf = (*ppPriv)->data;
 * @endcode
 *
 */
typedef tMKxStatus (*fMKx_RxAlloc) (struct MKx *pMKx,
                                    unsigned int BufLen,
                                    uint8_t **ppBuf,
                                    void **ppPriv);

/**
 * @brief A callback invoked by the LLC to deliver a receive packet buffer to
 *        the stack
 * @param pMKx MKx handle
 * @param pRxPkt Pointer to the receive packet.
 *            (same as @c *ppBuf provided in @ref fMKx_RxAlloc)
 * @param pPriv Private packet pointer
 *             (same as provided in @ref fMKx_RxAlloc)
 * @return MKXSTATUS_SUCCESS if the receive packet allocation delivery was
 *         successful. Other values may be logged by the MKx for debug purposes.
 *
 */
typedef tMKxStatus (*fMKx_RxInd) (struct MKx *pMKx,
                                  tMKxRxPacket *pRxPkt,
                                  void *pPriv);

/// Signalled notifications via MKx_NotifInd()
typedef enum
{
  // Useful masks
  MKX_NOTIF_MASK_ERROR       = 0x8000000, ///< Error
  MKX_NOTIF_MASK_UTC         = 0x4000000, ///< UTC boundary (PPS)
  MKX_NOTIF_MASK_STATS       = 0x2000000, ///< Statistics updated
  MKX_NOTIF_MASK_ACTIVE      = 0x1000000, ///< Radio channel active
  MKX_NOTIF_MASK_CONFIG      = 0x0800000, ///< Radio configuration completed
  MKX_NOTIF_MASK_RADIOA      = 0x0000010, ///< Specific to radio A
  MKX_NOTIF_MASK_RADIOB      = 0x0000020, ///< Specific to radio B
  MKX_NOTIF_MASK_CHANNEL0    = 0x0000001, ///< Specific to channel 0
  MKX_NOTIF_MASK_CHANNEL1    = 0x0000002, ///< Specific to channel 1
  MKX_NOTIF_MASK_CALIBRATION = 0x0000040, ///< Calibration
  MKX_NOTIF_MASK_TEMP        = 0x0000080, ///< Temperature measurement
  MKX_NOTIF_MASK_AUXADC      = 0x0000100, ///< AuxADC measurement
  MKX_NOTIF_MASK_AUXADCCFG   = 0x0000200, ///< AuxADC configuration
  /// No notification
  MKX_NOTIF_NONE          = 0x0000000,
  /// Active: Radio A, Channel 0
  MKX_NOTIF_ACTIVE_A0     = MKX_NOTIF_MASK_ACTIVE | MKX_NOTIF_MASK_RADIOA |
                            MKX_NOTIF_MASK_CHANNEL0,
  /// Active: Radio A, Channel 1
  MKX_NOTIF_ACTIVE_A1     = MKX_NOTIF_MASK_ACTIVE | MKX_NOTIF_MASK_RADIOA |
                            MKX_NOTIF_MASK_CHANNEL1,
  /// Active: Radio B, Channel 0
  MKX_NOTIF_ACTIVE_B0     = MKX_NOTIF_MASK_ACTIVE | MKX_NOTIF_MASK_RADIOB |
                            MKX_NOTIF_MASK_CHANNEL0,
  /// Active: Radio B, Channel 1
  MKX_NOTIF_ACTIVE_B1     = MKX_NOTIF_MASK_ACTIVE | MKX_NOTIF_MASK_RADIOB |
                            MKX_NOTIF_MASK_CHANNEL1,
  /// Stats updated: Radio A, Channel 0
  MKX_NOTIF_STATS_A0      = MKX_NOTIF_MASK_STATS  | MKX_NOTIF_MASK_RADIOA |
                            MKX_NOTIF_MASK_CHANNEL0,
  /// Stats updated: Radio A, Channel 1
  MKX_NOTIF_STATS_A1      = MKX_NOTIF_MASK_STATS  | MKX_NOTIF_MASK_RADIOA |
                            MKX_NOTIF_MASK_CHANNEL1,
  /// Stats updated: Radio B, Channel 0
  MKX_NOTIF_STATS_B0      = MKX_NOTIF_MASK_STATS  | MKX_NOTIF_MASK_RADIOB |
                            MKX_NOTIF_MASK_CHANNEL0,
  /// Stats updated: Radio B, Channel 1
  MKX_NOTIF_STATS_B1      = MKX_NOTIF_MASK_STATS  | MKX_NOTIF_MASK_RADIOB |
                            MKX_NOTIF_MASK_CHANNEL1,
  /// UTC second boundary
  MKX_NOTIF_UTC           = MKX_NOTIF_MASK_UTC,
  /// Calibration update
  MKX_NOTIF_CALIBRATION   = MKX_NOTIF_MASK_CALIBRATION,
  /// Temperature measurement update
  MKX_NOTIF_TEMP          = MKX_NOTIF_MASK_TEMP,
  /// AuxADC configuration update
  MKX_NOTIF_AUXADCCFG     = MKX_NOTIF_MASK_AUXADCCFG,
  /// AuxADC measurement update
  MKX_NOTIF_AUXADC        = MKX_NOTIF_MASK_AUXADC,
  /// Error
  MKX_NOTIF_ERROR         = MKX_NOTIF_MASK_ERROR
} eMKxNotif;
/// @copydoc eMKxNotif
typedef uint32_t tMKxNotif;

/**
 * @brief MKx notification callback
 * @param pMKx MKx handle
 * @param Notif The notification
 * @return MKXSTATUS_SUCCESS if the 'notif' was successfully handled.
 *         Other values are logged for debug purposes.
 *
 * Notification that the
 *  - Radio has encountered a UTC boundary
 *  - Channel is now active
 *  - Radio/Channel has experienced an error
 *  - Temperature update
 *  - AuxADC or AuxADCCfg update
 */
typedef tMKxStatus (*fMKx_NotifInd) (struct MKx *pMKx,
                                     tMKxNotif Notif);

/**
 * @brief Request a change to the calibration configuration
 * @param pMKx MKx handle
 * @param pCfg Pointer to the new configuration to apply
 * @return MKXSTATUS_SUCCESS if the request was accepted
 *
 * If the configuration register inside pCfg is set to -1U, no change in
 * settings will occur and the device will simply respond with the current
 * configuration.
 */
typedef tMKxStatus (*fMKx_Calibration) (struct MKx *pMKx,
                                        tMKxCalibration *pCalib);

/**
 * @brief Request a change to the auxiliary ADC configuration
 * @param pMKx MKx handle
 * @param pCfg Pointer to the new configuration to apply
 * @return MKXSTATUS_SUCCESS if the request was accepted
 *
 * If the configuration register inside pCfg is set to -1U, no change in
 * settings will occur and the device will simply respond with the current
 * configuration.
 */
typedef tMKxStatus (*fMKx_AuxADCCfg) (struct MKx *pMKx,
                                      tMKxAuxADCConfig *pCfg);

/**
 * @brief A callback invoked by the LLC to deliver auxiliary ADC data
 * @param pMKx MKx handle
 * @param pMsg Pointer to the buffer.
 * @return MKXSTATUS_SUCCESS if the receive packet allocation delivery was
 *         successful. Other values may be logged by the MKx for debug purposes.
 *
 * ADC data is sent from the radio at the end of a round-robin cycle
 * @note pBuf must be handled (or copied) in the callback
 */
typedef tMKxStatus (*fMKx_AuxADCInd) (struct MKx *pMKx,
                                      const struct MKxIFMsg *pMsg);

/**
 * @brief Update the PA temperature measurement
 * @param pMKx MKx handle
 * @param pTemp Pointer to the new measurements to apply
 * @return MKXSTATUS_SUCCESS if the request was accepted
 *
 * @code
 * # Get the current/default temperature
 * tMKxTemp Temp = {0,};
 * memcpy(&(Temp.TempData), &(pMKx->State.Temp), sizeof(Temp));
 * # Update both the temperatures
 * Temp.TempData.TempPAAnt1 = 42;
 * Temp.TempData.TempPAAnt2 = 67;
 * ...
 * # Deliver the measurements
 * Res = MKx_Temp(pMKx, &Temp);
 * @endcode
 */
typedef tMKxStatus (*fMKx_Temp) (struct MKx *pMKx,
                                 tMKxTemp *pTemp);

/**
 * @brief Request to get the underlying MKx TSF.
 * @param pMKx MKx handle
 * @return MKXSTATUS_SUCCESS if the request was accepted
 *
 * TSF is returned via fMKx_GetTSFInd callback.
 */
typedef tMKxStatus (*fMKx_GetTSFReq) (struct MKx *pMKx);

/**
 * @brief A callback invoked by the LLC to deliver the current TSF to the stack
 * @param pMKx MKx handle
 * @param TSF The TSF counter value
 * @return MKXSTATUS_SUCCESS if the receive packet allocation delivery was
 *         successful. Other values may be logged by the MKx for debug purposes.
 *
 */
typedef tMKxStatus (*fMKx_GetTSFInd) (struct MKx *pMKx, tMKxTSF TSF);

/**
 * @brief Set the MKx TSF to UTC time, using either 1PPS event or TSF timestamp
 * @param pMKx MKx handle
 * @param pSetTSF Pointer to data structure containing UTC set
 * @return MKXSTATUS_SUCCESS (0) or a negative error code @sa eMKxStatus
 *
 * When pSetTSF->SetTSFData.Cmd == UTC_AT_1PPS,
 * - Set MKx TSF using UTC input, which is the time that corresponded to the
 *   last 1PPS event.
 *
 * When pSetTSF->SetTSFData.Cmd == UTC_AT_TSF,
 * - Set MKx TSF using UTC input, which is the UTC time that corresponds to the
 *   TSF timestamp input.
 */
typedef tMKxStatus (*fMKx_SetTSF) (struct MKx *pMKx, tMKxSetTSF *pSetTSF);

/**
 * @brief Request to control / read GPIO3
 * @param pMKx MKx handle
 * @param pGPIOMsg GPIO control message
 * @return MKXSTATUS_SUCCESS if the request was accepted
 *
 * GPIO information is returned via fMKx_GPIOInd callback.
 */
typedef tMKxStatus (*fMKx_GPIOReq) (struct MKx *pMKx,
                                    tMKxGPIO *pGPIOMsg);

/**
 * @brief A callback invoked by the LLC to deliver the GPIO information
 * @param pMKx MKx handle
 * @param pGPIOMsg Pointer to GPIO Message containing information
 *
 * Note that it is important to check the return code in the MKxIFMsg header
 * to determine if the GPIO command succeded.
 */
typedef tMKxStatus (*fMKx_GPIOInd) (struct MKx *pMKx,
                                    const tMKxGPIO *pGPIOMsg);

/**
 * @brief Function invoked by the stack to deliver a C2X APDU Msg to the SAF5x00
 * @param pMKx MKx handle
 * @param pMsg Pointer to the buffer.
 * @return MKXSTATUS_SUCCESS if the buffer was sent successful.
 *         Other values may be logged by the MKx for debug purposes.
 *
 * @note This function blocks until the buffer is sent on-the-wire
 */
typedef tMKxStatus (*fC2XSec_CommandReq) (struct MKx *pMKx,
                                          tMKxC2XSec *pMsg);
/**
 * @brief Callback invoked by the LLC to deliver the C2X result to the stack
 * @param pMKx MKx handle
 * @param pMsg Pointer to the buffer.
 * @return MKXSTATUS_SUCCESS if the receive packet allocation delivery was
 *         successful. Other values may be logged by the MKx for debug purposes.
 *
 * @note pBuf must be handled (or copied) in the callback
 */
typedef tMKxStatus (*fC2XSec_ResponseInd) (struct MKx *pMKx,
                                           const tMKxC2XSec *pMsg);

/**
 * @brief A function used to send a logging command to the radio
 * @param pMKx MKx handle
 * @param LogType The log instruction
 * @return MKXSTATUS_SUCCESS if the buffer was sent successful.
 *         Other values may be logged by the MKx for debug purposes.
 *
 * @note This function blocks until the buffer is sent on-the-wire
 */
typedef tMKxStatus (*fMKx_LogReq)(struct MKx *pMKx,
                                  tMKxLogType LogType);

/**
 * @brief Callback invoked to deliver a received log message from the radio
 * @param pMKx MKx handle
 * @param pMsg Pointer to the log message
 * @return MKXSTATUS_SUCCESS if the 'log' was successfully handled.
 *
 * A log message from the radio for the host
 */
typedef tMKxStatus (*fMKx_LogInd)(struct MKx *pMKx,
                                  const tMKxLog *pMsg);

/**
 * @brief A function used to send a loopback message
 * @param pMKx MKx handle
 * @param pMsg Pointer to the loopback message
 * @return MKXSTATUS_SUCCESS if the buffer was sent successful.
 *         Other values may be logged by the MKx for debug purposes.
 *
 * @note This function blocks until the buffer is sent on-the-wire
 */
typedef tMKxStatus (*fMKx_LoopbackReq)(struct MKx *pMKx,
                                       tMKxLoopback *pMsg);

/**
 * @brief Callback invoked to deliver a received loopback message from the radio
 * @param pMKx MKx handle
 * @param pMsg Pointer to the return loopback message
 * @return MKXSTATUS_SUCCESS if the message was successfully handled.
 *
 * A loopback message from the radio for the host
 */
typedef tMKxStatus (*fMKx_LoopbackInd)(struct MKx *pMKx,
                                       const tMKxLoopback *pMsg);

/**
 * @brief A function used to send a fault message
 * @param pMKx MKx handle
 * @param pMsg Pointer to the fault message
 * @return MKXSTATUS_SUCCESS if the buffer was sent successful.
 *         Other values may be logged by the MKx for debug purposes.
 *
 * Fault messages are used to set a fault (for test purposes), clear the
 * fail-safe state or to obtain the fault state.
 * Only supported in for the functional safety SAF5300/SAF5400 devices.
 * @note This function blocks until the buffer is sent on-the-wire
 */
typedef tMKxStatus (*fMKx_FaultReq)(struct MKx *pMKx,
                                    tMKxFault *pMsg);

/**
 * @brief Callback invoked to deliver a received fault message from the radio
 * @param pMKx MKx handle
 * @param pMsg Pointer to the return fault message
 * @return MKXSTATUS_SUCCESS if the message was successfully handled.
 *
 * A clear fault response message from the radio
 */
typedef tMKxStatus (*fMKx_FaultInd)(struct MKx *pMKx,
                                    const tMKxFault *pMsg);

/**
 * @brief A function used to senda reset request message
 * @param pMKx MKx handle
 * @param pMsg The reset message
 * @return MKXSTATUS_SUCCESS if the buffer was sent successful.
 *         Other values may be logged by the MKx for debug purposes.
 *
 * Function results in a warm reset being performed on the SAF5x00 device.
 * Only supported in SAF5300/SAF5400 devices.
 * @note This function blocks until the buffer is sent on-the-wire
 */
typedef tMKxStatus (*fMKx_ResetReq)(struct MKx *pMKx,
                                    tMKxReset *pMsg);

/**
 * @brief Callback invoked to deliver a received error message from the radio
 * @param pMKx MKx handle
 * @param pMsg Pointer to the Error message
 * @return MKXSTATUS_SUCCESS if the Error was successfully handled.
 *
 * Callback function, called when an error message (MKXIF_ERROR) is received
 * from the SAF5x00 device.  This event corresponds to the SAF5x00 going into
 * a fault state.
 */
typedef tMKxStatus (*fMKx_ErrorInd)(struct MKx *pMKx,
                                    const tMKxIFMsg *pMsg);

/**
 * @brief A function invoked by the stack to deliver a debug buffer to the MKx
 * @param pMKx MKx handle
 * @param pMsg Pointer to the buffer.
 * @return MKXSTATUS_SUCCESS if the buffer was sent successful.
 *         Other values may be logged by the MKx for debug purposes.
 *
 * @note This function blocks until the buffer is sent on-the-wire
 */
typedef tMKxStatus (*fMKx_DebugReq) (struct MKx *pMKx,
                                     struct MKxIFMsg *pMsg);
/**
 * @brief A callback invoked by the LLC to deliver a debug buffer to the stack
 * @param pMKx MKx handle
 * @param pMsg Pointer to the buffer.
 * @return MKXSTATUS_SUCCESS if the receive packet allocation delivery was
 *         successful. Other values may be logged by the MKx for debug purposes.
 *
 * @note pBuf must be handled (or copied) in the callback
 */
typedef tMKxStatus (*fMKx_DebugInd) (struct MKx *pMKx,
                                     const struct MKxIFMsg *pMsg);

/**
 * @brief A function invoked by the stack to request the API Version of the MKx
 * @param pMKx MKx handle
 * @param pMsg Pointer to the buffer.
 * @return MKXSTATUS_SUCCESS if the buffer was sent successful.
 *         Other values may be logged by the MKx for debug purposes.
 *
 * @note This function blocks until the buffer is sent on-the-wire
 */
typedef tMKxStatus (*fMKx_VersionReq) (struct MKx *pMKx,
                                       struct MKxIFMsg *pMsg);

//------------------------------------------------------------------------------
// Handle Structures
//------------------------------------------------------------------------------

/// MKx LLC status information (including statistics)
typedef struct MKxState
{
  /// Statistics (read only)
  tMKxRadioStatsData Stats[MKX_RADIO_COUNT];
  /// Temperature measurements (read only)
  tMKxTempData Temp;
  /// Auxiliary ADC measurements (read only)
  tMKxAuxADCData AuxADC;
} __attribute__((__packed__)) tMKxState;

/// Global MKx MKx API functions
typedef struct MKxFunctions
{
  fMKx_Config Config;
  fMKx_TxReq TxReq;
  fMKx_GetTSFReq GetTSFReq;
  fMKx_SetTSF SetTSF;
  fMKx_TxFlush TxFlush;
  fMKx_Calibration Calibration;
  fMKx_Temp Temp;
  fMKx_DebugReq DebugReq;
  fC2XSec_CommandReq C2XSecCmd;
  fMKx_AuxADCCfg AuxADCCfg;
  fMKx_LogReq LogReq;
  fMKx_LoopbackReq LoopbackReq;
  fMKx_FaultReq FaultReq;
  fMKx_ResetReq ResetReq;
  fMKx_GPIOReq GPIOReq;
  fMKx_VersionReq VersionReq;
} tMKxFunctions;

/// Global MKx MKx API callbacks (set by the stack)
typedef struct MKxCallbacks
{
  fMKx_TxCnf          TxCnf;
  fMKx_RxAlloc        RxAlloc;
  fMKx_RxInd          RxInd;
  fMKx_NotifInd       NotifInd;
  fMKx_DebugInd       DebugInd;
  fMKx_GetTSFInd      GetTSFInd;
  fC2XSec_ResponseInd C2XSecRsp;
  fMKx_AuxADCInd      AuxADCInd;
  fMKx_LogInd         LogInd;
  fMKx_LoopbackInd    LoopbackInd;
  fMKx_FaultInd       FaultInd;
  fMKx_ErrorInd       ErrorInd;
  fMKx_GPIOInd        GPIOInd;
  // Require an even number of function pointers for 64bit alignment
  uintptr_t           Padding;
} tMKxCallbacks;

/// MKx API functions and callbacks
typedef struct MKxAPI
{
  /// Stack -> SDR
  tMKxFunctions Functions;
  /// SDR -> Stack
  tMKxCallbacks Callbacks;
} tMKxAPI;

/// MKx LLC configuration
typedef struct MKxConfig
{
  /// Radio configuration (read only)
  tMKxRadioConfigData Radio[MKX_RADIO_COUNT];
  /// Calibration configuration
  tMKxCalibrationData Calibration;
  /// AuxADC configuration
  tMKxAuxADCConfigData AuxADC;
} __attribute__((__packed__)) tMKxConfig;

/// MKx LLC handle, 64 bit alignment required
typedef struct MKx
{
  /// 'Magic' value used as an indicator that the handle is valid
  uint32_t Magic;
  /// Major version number. Mismatch results in blocked communications
  uint16_t Major;
  /// Reserved (for 64bit alignment)
  uint16_t Reserved;
  /// Private data (for the stack to store stuff)
  union {
    void *pPriv;
    uint64_t Priv;
  };
  /// State information (read only)
  const tMKxState State;
  /// Configuration (read only)
  const tMKxConfig Config;
  /// MKx API functions and callbacks
  struct MKxAPI API;
} tMKx;

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

/**
 * @brief Initialise the LLC and get a handle
 * @param DevId Device number (0..1)
 * @param ppMKx MKx handle to initialise
 * @return MKXSTATUS_SUCCESS (0) or a negative error code @sa eMKxStatus
 *
 * This function will:
 *  - Optionally reset and download the SDR firmware
 *   - The SDR firmware image may be complied into the driver as a binary object
 *  - Initialise the USB, SDIO, SPI or Ethernet UDP interface
 */
tMKxStatus MKx_Init(uint8_t DevId, tMKx **ppMKx);

/**
 * @brief De-initialise the LLC
 * @param pMKx MKx handle
 * @return MKXSTATUS_SUCCESS (0) or a negative error code @sa eMKxStatus
 *
 */
tMKxStatus MKx_Exit(tMKx *pMKx);


/**
 * @copydoc fMKx_Config
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_Config(tMKx *pMKx,
                                    tMKxRadio Radio,
                                    tMKxRadioConfig *pConfig)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (Radio > (tMKxRadio)MKX_RADIO_MAX)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else if (pConfig == (tMKxRadioConfig *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.Config(pMKx, Radio, pConfig);
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_TxReq
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_TxReq(tMKx *pMKx,
                                   tMKxTxPacket *pTxPkt,
                                   void *pPriv)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.TxReq(pMKx, pTxPkt, pPriv);
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_TxFlush
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_TxFlush(tMKx *pMKx,
                                     tMKxRadio RadioID,
                                     tMKxChannel ChannelID,
                                     tMKxTxQueue TxQueue)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.TxFlush(pMKx, RadioID, ChannelID, TxQueue);
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_GetTSFReq
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_GetTSFReq(tMKx *pMKx)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.GetTSFReq(pMKx);
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_SetTSF
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_SetTSF(tMKx *pMKx, tMKxSetTSF *pSetTSF)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.SetTSF(pMKx, pSetTSF);
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_GPIOReq
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_GPIOReq(tMKx *pMKx,
                                     tMKxGPIO *pGPIOMsg)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.GPIOReq(pMKx, pGPIOMsg);
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_VersionReq
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_VersionReq(tMKx *pMKx,
                                        tMKxIFMsg *pMsg)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.VersionReq(pMKx, pMsg);
  }
  return ReturnCode;
}

/**
 * @brief Helper function to read the Auxiliary ADC measurements
 * @param pMKx MKx handle
 * @param pAuxADCData Storage to place the ADC measurements in
 * @return MKXSTATUS_SUCCESS on success or a negative MKxStatus value
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_GetAuxADC(const struct MKx *pMKx,
                                      tMKxAuxADCData *pAuxADCData)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else
  {
    (void)memcpy(pAuxADCData, &(pMKx->State.AuxADC), sizeof(tMKxAuxADCData));
    ReturnCode = (tMKxStatus)MKXSTATUS_SUCCESS;
  }
  return ReturnCode;
}

/**
 * @brief Helper function to read the MKx statistics
 * @param pMKx MKx handle
 * @param Radio the selected radio
 * @param pStats Storage to place the radio's statistics in
 * @return MKXSTATUS_SUCCESS on success or a negative MKxStatus value
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_GetStats(const struct MKx *pMKx,
                                      tMKxRadio Radio,
                                      tMKxRadioStatsData *pStats)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (Radio > (tMKxRadio)MKX_RADIO_MAX)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else if (pStats == (tMKxRadioStatsData *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    (void)memcpy(pStats, &(pMKx->State.Stats[Radio]),
                 sizeof(tMKxRadioStatsData));
    ReturnCode = (tMKxStatus)MKXSTATUS_SUCCESS;
  }

  return ReturnCode;
}

/**
 * @copydoc fMKx_AuxADCCfg
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_SetAuxADCCfg(tMKx *pMKx,
                                          tMKxAuxADCConfig *pCfg)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pCfg == (tMKxAuxADCConfig *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.AuxADCCfg(pMKx, pCfg);
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_AuxADCCfg
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_GetAuxADCCfg(tMKx *pMKx,
                                          tMKxAuxADCConfig *pCfg)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pCfg == (tMKxAuxADCConfig *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    (void)memset(&(pCfg->AuxADCConfigData), 0xFF, sizeof(tMKxAuxADCConfigData));
    (void)pMKx->API.Functions.AuxADCCfg(pMKx, pCfg);
    (void)memcpy(&(pCfg->AuxADCConfigData), &(pMKx->Config.AuxADC),
                 sizeof(tMKxAuxADCConfigData));
    ReturnCode = (tMKxStatus)MKXSTATUS_SUCCESS;
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_Temp
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_SetTemp(tMKx *pMKx,
                                     tMKxTemp *pTemp)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pTemp == (tMKxTemp *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.Temp(pMKx, pTemp);
  }
  return ReturnCode;
}

/**
 * @brief Helper function to read the MKx temperature measurements
 * @param pMKx MKx handle
 * @param pTemp Storage to place the temperature measurements in
 * @return MKXSTATUS_SUCCESS on success or a negative MKxStatus value
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_GetTemp(tMKx *pMKx,
                                     tMKxTemp *pTemp)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pTemp == (tMKxTemp *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    // Send a bogus 'MKX_IF_TEMP' message so that the MKx replies with internal
    // measurements
    (void)memset(&(pTemp->TempData), 0x80, sizeof(tMKxTempData));
    (void)pMKx->API.Functions.Temp(pMKx, pTemp);
    // Get the latest values from the MKx handle
    (void)memcpy(&(pTemp->TempData), &(pMKx->State.Temp), sizeof(tMKxTempData));
    ReturnCode = (tMKxStatus)MKXSTATUS_SUCCESS;
  }
  return ReturnCode;
}

/**
 * @copydoc fMKx_Calibration
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_SetCalibration(tMKx *pMKx,
                                            tMKxCalibration *pCalib)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pCalib == (tMKxCalibration *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    ReturnCode = pMKx->API.Functions.Calibration(pMKx, pCalib);
  }
  return ReturnCode;
}

/**
 * @brief Helper function to read the MKx antenna configuration
 * @param pMKx MKx handle
 * @param pCalib Storage to place the calibration data in
 * @return MKXSTATUS_SUCCESS on success or a negative MKxStatus value
 */
DISABLE_MISRA("coverity compliance deviate MISRA_C_2012_Rule_8_13");
static INLINE tMKxStatus MKx_GetCalibration(tMKx *pMKx,
                                            tMKxCalibration *pCalib)
{
  tMKxStatus ReturnCode;

  if (pMKx == (tMKx *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pMKx->Magic != MKX_API_MAGIC)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_HANDLE;
  }
  else if (pCalib == (tMKxCalibration *)NULL)
  {
    ReturnCode = (tMKxStatus)MKXSTATUS_FAILURE_INVALID_PARAM;
  }
  else
  {
    // Send a bogus 'MKX_IF_CALIBRATION' message so that the MKx replies with
    // internal values
    (void)memset(&(pCalib->CalibrationData), 0x80, sizeof(tMKxCalibrationData));
    (void)pMKx->API.Functions.Calibration(pMKx, pCalib);
    // Get the latest values from the MKx handle
    (void)memcpy(&(pCalib->CalibrationData), &(pMKx->Config.Calibration),
                 sizeof(tMKxCalibrationData));
    ReturnCode = (tMKxStatus)MKXSTATUS_SUCCESS;
  }
  return ReturnCode;
}
#endif

#ifdef __cplusplus
}
#endif

#endif // #ifndef LINUX__COHDA__LLC__LLC_API_H__
