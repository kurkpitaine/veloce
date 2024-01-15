use crate::wire::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};

enum_with_unknown! {
    /// Types for the LLCRemote message transfers.
    pub enum Message(u16) {
        /// LLC API Version.
        ApiVersion  = 0,
        /// A transmit packet.
        TxPacket    = 1,
        /// A received packet.
        RxPacket    = 2,
        /// New UTC Time.
        SetTSF      = 3,
        /// Transmitted packet event.
        TxEvent     = 4,
        /// Radio config for Radio A.
        RadioACfg   = 5,
        /// Radio config for Radio B.
        RadioBCfg   = 6,
        /// Radio A statistics.
        RadioAStats = 7,
        /// Radio B statistics.
        RadioBStats = 8,
        /// Flush a single queue or all queues.
        FlushQueue  = 9,
        /// A generic debug container.
        Debug       = 10,
        /// C2XSEC message.
        C2xSec      = 11,
        /// Calibration config message.
        Calibration = 12,
        /// Temperature measurement message.
        Temp        = 13,
        /// Read the current UTC Time.
        GetTsf      = 14,
        /// Auxiliary ADC message.
        AuxADC      = 15,
        /// Auxiliary ADC config message.
        AuxADCCfg   = 16,
        /// Error event message.
        Error       = 17,
        /// Warning event message.
        Warning     = 18,
        /// Log messages.
        Log         = 19,
        /// GPIO control messages.
        Gpio        = 20,
        /// Warm reset instruction to the radio
        Reset       = 21,
        /// Host radio loopback message.
        Loopback    = 22,
        /// Fault message.
        Fault       = 23,

    }
}

enum_with_unknown! {
    /// NXP LLC interface return codes.
    /// -1 to -255 reserved for errno values.
    pub enum Status(i16) {
        /// Success return code
        Success = 0,
        /// Received MKXIF message with unexpected or invalid type
        InvalidMkxifType                  = -256,
        /// Unspecified failure return code (catch-all)
        FailureInternalError              = -257,
        /// Failure due to invalid MKx Handle
        FailureInvalidHandle              = -258,
        /// Failure due to invalid length of the received message
        FailureInvalidLength              = -260,
        /// Failure due to invalid parameter setting
        FailureInvalidParam               = -261,
        /// Auto-cal requested when radio is running auto-cal
        FailureAutocalRejectSimultaneous  = -262,
        /// Auto-cal requested but radio is not configured
        FailureAutocalRejectUnconfigured  = -263,
        /// Failure due to invalid Calibration data
        FailureInvalidCalibration         = -264,
        /// Failure due to invalid version of the calibration data
        FailureInvalidCalibrationVersion  = -265,
        /// Failure due to invalid Radio
        FailureInvalidRadio               = -266,
        /// Message rejected as radio is currently in fail safe state
        RejectedFailSafeState             = -267,
        /// Radio config failed (likely to be a hardware fault) maximum
        FailureRadioconfigMax             = -513,
        /// Rdio config failed (generic)
        FailureRadioconfigGeneric         = -766,
        /// Radio config failed (likely to be a hardware fault) minimum
        FailureRadioconfigMin             = -768,
        /// Packet failed by exceeding Time To Live
        TxFailTtl                         = -769,
        /// Packet failed by exceeding Max Retry count
        TxFailRetries                     = -770,
        /// Packet failed because queue was full
        TxFailQueuefull                   = -771,
        /// Packet failed because requested radio is not present
        TxFailRadioNotPresent             = -772,
        /// Packet failed because the frame was malformed
        TxFailMalformed                   = -773,
        /// Packet failed in the PHY because the frame was malformed
        TxFailMalformedAtPhy              = -774,
        /// Packet failed because requested radio is not present
        TxFailRadioUnconfined             = -775,
        /// Packet failed because it was too long
        TxFailPacketTooLong               = -776,
        /// Packet failed because DMA failure
        TxFailDma                         = -777,
        /// Packet failed because of malformed antenna
        TxFailInvalidAntenna              = -778,
        /// Packet failed because radio is currently in fail safe state
        TxFailFailSafeState               = -779,
        /// Packet failed because of a host to MKx interface problem
        TxFailHostRadioInterfaceProblem   = -780,
        /// TxEvent upload failed at the DSP
        TxEventUploadFailDsp              = -800,
        /// Ant1 I2C Temperature sensor read failure
        I2cTempAnt1Failure                = -810,
        /// Ant2 I2C Temperature sensor read failure
        I2cTempAnt2Failure                = -811,
        /// Ant1 ANALOG Temperature sensor read failure (SAF5400 Only)
        AnalogTempAnt1Failure             = -812,
        /// Ant2 ANALOG Temperature sensor read failure (SAF5400 Only)
        AnalogTempAnt2Failure             = -813,
        /// SAF5400 Internal Temperature sensor read failure (SAF5400 Only - Unused)
        InternalTempFailure               = -814,
        /// Overflow of packets at the RxMAC on the DSP
        RxMacBufferOverflowDsp            = -832,
        /// Security message failed due to security accelerator not being present
        SecurityAcceleratorNotPresent     = -1024,
        /// Security message failed due to security FIFO being full
        SecurityFifoFull                  = -1025,
        /// Security message failed due to internal corruption
        SecurityInternalError             = -1026,
        /// Security message failed due to incoming message length too short
        SecurityMsgTooShort              = -1027,
        /// Invalid MKxGPIO Command
        GpioInvalidCmd                   = -1100,
        /// GPIO message failed due to FIFO being full
        GpioFifoFull                     = -1101,
        /// Received MKXIF Debug message with unexpected or invalid type
        InvalidDebugMsgType              = -1102,
        /// Reserved
        Reserved                         = -16166,
    }
}

enum_with_unknown! {
    /// NXP LLC SAF5x00 return codes.
    pub enum SafStatus(i16) {
          /// No error
  Success = 0,
  /// Received MKXIF message with unexpected or invalid type
  InvalidMkxifType                      = -10000,
  /// Upload message type or length was corrupted
  HostUploadMsgCorrupted               = -10001,
  /// DSP fault asserted without an error code
  DspUnknown                             = -10002,
  /// Test fault condition reported by DSP, commanded by host message
  DspFaultTest                        = -10003,
  /// Test fault condition reported by ARM, commanded by host message
  ARM_FAULT_TEST                          = -10004,
  /// Attempted to access a radio that does not exist in the system
  RADIOB_UNSUPPORTED                      = -10005,
  /// Internal DSP to ARM Interrupt failure (DSP side)
  DSP_TESTFAULT_FAILED                    = -10006,
  /// Internal DSP to ARM Interrupt failure (ARM side)
  ARM_TESTFAULT_FAILED                    = -10007,
  /// Exception occurred on the DSP
  DSP_EXCEPTION                           = -10008,
  /// Timeout (1s) waiting for DSP to be available to process RadioConfig msg
  RADIOCONFIG_TIMEOUT                     = -10009,
  /// Error reading the one-time programmable (OTP) data
  OTP_FAILURE                             = -10010,
  /// Attempted to retire a frame with queue index out of bounds
  TXQUEUE_INDEX_OUT_OF_BOUNDS             = -10100,
  /// Attempted to retire a frame with a null QED
  TXQUEUE_NULL_QED                        = -10101,
  /// Attempted to retire a frame with a null queue pointer
  TXQUEUE_NULL_QUEUEPTR                   = -10102,
  /// Attempted to retire a frame with a null TxPkt pointer
  TxqueueNullTxpkt                      = -10103,
  /// Attempted to flush txqueue but locked up
  TXQUEUE_FLUSH_WATCHDOG                  = -10104,
  /// Attempted to fail frame exchange on an inactive queue number
  TXQUEUE_INACTIVE_QUEUENUM_FAILFEX       = -10105,
  /// UPL DMA lockup error where write pointer is not updated during tx
  TX_UPL_DMA_WRPTR_LOCKUP                 = -10200,
  /// ARM received invalid ARMCmd type from the DSP
  INVALID_ARM_CMD                         = -10300,
  /// DSP received an invalid command from the ARM
  INVALID_DSP_CMD                         = -10301,
  /// Read or Write request when EEPROM was not detected on boot
  EEPROM_NOT_PRESENT                      = -10400,
  /// Importing of calibration data failed due to EEPROM not being programmed
  EEPROM_NOT_PROGRAMMED                   = -10401,
  /// EEPROM sleep command timed out indicating internal ARM timer has stopped
  EEPROM_SLEEP_TIMEOUT                    = -10402,
  /// EEPROM read timeout event from I2C driver
  EEPROM_READ_TIMEOUT                     = -10403,
  /// EEPROM read failed event from I2C driver
  EEPROM_READ_FAILED                      = -10404,
  /// EEPROM read incomplete where not all requested bytes were read
  EEPROM_READ_INCOMPLETE                  = -10405,
  /// EEPROM read overflow where more bytes than requested were read
  EEPROM_OVERREAD                         = -10406,
  /// EEPROM I2C driver failed to set device address for read
  EEPROM_READ_SET_DEVICE_ADDR_FAILED      = -10407,
  /// EEPROM I2C write failed to set address for upcoming read
  EEPROM_READ_SET_ADDR_FAILED             = -10408,
  /// EEPROM write timeout event from I2C driver
  EEPROM_WRITE_TIMEOUT                    = -10409,
  /// EEPROM write failed event from I2C driver
  EEPROM_WRITE_FAILED                     = -10410,
  /// EEPROM write incomplete where not all requested bytes were written
  EEPROM_WRITE_INCOMPLETE                 = -10411,
  /// EEPROM overflow where more bytes were written than requested
  EEPROM_OVERWRITE                        = -10412,
  /// EEPROM I2C driver failed to set device address for write
  EEPROM_WRITE_SET_DEVICE_ADDR_FAILED     = -10413,
  /// Bank requested is out of range (Range 0 to 3)
  EEPROM_INVALID_BANK                     = -10414,
  /// Magic number in EEPROM is incorrect for import
  EEPROM_INVALID_MAGIC                    = -10415,
  /// Version number in EEPROM is incorrect for import
  EEPROM_INVALID_VERSION                  = -10416,
  /// Calculated CRC of EEPROM data did not match for import
  EEPROM_INVALID_CRC                      = -10417,
  /// Write to bank 1 attempted but bank locked as magic number has been set
  EEPROM_BANK_LOCKED                      = -10418,
  /// Memory access request is outside of valid range
  INVALID_MEMORY_RANGE                    = -10500,
  /// Capture timed out
  CAPTURE_TIMEOUT                         = -10600,
  /// Invalid TXPHY Register (Out of range)
  INVALID_TXPHY_REGISTER                  = -10700,
  /// Invalid RXPHY Register (Out of range)
  INVALID_RXPHY_REGISTER                  = -10701,
  /// Invalid CALIB Register (Out of range)
  INVALID_CALIB_REGISTER                  = -10702,
  /// Invalid ARM Register (Out of range)
  INVALID_ARM_REGISTER                    = -10703,
  /// Invalid RFE Register (Out of range)
  INVALID_RFE_REGISTER                    = -10704,
  /// Invalid EEPROM0 Register (Out of range)
  INVALID_EEPROM0_REGISTER                = -10705,
  /// Invalid EEPROM1 Register (Out of range)
  INVALID_EEPROM1_REGISTER                = -10706,
  /// Invalid EEPROM2 Register (Out of range)
  INVALID_EEPROM2_REGISTER                = -10707,
  /// Invalid Bank Read (Out of range)
  INVALID_BANK_READ                       = -10708,
  /// Invalid Bank Write (Out of range)
  INVALID_BANK_WRITE                      = -10709,
  /// Invalid MKxGPIO Command at the DSP
  GPIO_INVALID_CMD                        = -10800,
  /// GPIO Internal Failure
  GPIO_INTERNAL_ERROR                     = -10801,
  /// Received ARM Log command with invalid type
  INVALID_ARMLOG_TYPE                     = -10900,
  /// Received DSP Log command with invalid type
  INVALID_DSPLOG_TYPE                     = -10901,
  /// Internal ARM Log error due to an internal corruption
  ARMLOG_INTERNAL_ERROR                   = -10902,
  /// C2XSec module received a message that is too short to even contain a USN
  C2XSEC_MSG_TOO_SHORT_NO_USN             = -11000,
  /// C2XSec module received a command that is too short in length
  C2XSEC_CMD_TOO_SHORT                    = -11001,
  /// C2XSec module received a message containing an unsupported instruction
  C2XSEC_INS_NOT_SUPPORTED                = -11002,
  /// C2XSec module received an invalid curve ID
  C2XSEC_CURVEID_INVALID                  = -11003,
  /// C2XSec module received a command whose length does not match its curve ID
  C2XSEC_SIZE_MISMATCH_FOR_CURVEID        = -11004,
  /// C2XSec module received a reconstruct ECC public key command with wrong LC
  C2XSEC_REPK_WRONG_LC                    = -11005,
  /// C2XSec module received a reconstruct ECC public key command with wrong
  /// length
  C2XSEC_REPK_WRONG_LENGTH                = -11006,
  /// C2XSec module received a decompress public key command with wrong LC
  C2XSEC_DPK_WRONG_LC                     = -11007,
  /// C2XSec module received a decompress public key command with wrong length
  C2XSEC_DPK_WRONG_LENGTH                 = -11008,
  /// C2XSec module received a verify signature of hash command with wrong LC
  C2XSEC_VSOH_WRONG_LC                    = -11009,
  /// C2XSec module received a verify signature of hash command with wrong
  /// length
  C2XSEC_VSOH_WRONG_LENGTH                = -11010,
  /// C2XSec module received a decompress public key and verify signature of
  /// hash command with wrong LC
  C2XSEC_DPK_VSOH_WRONG_LC                = -11011,
  /// C2XSec module received a decompress public key and verify signature of
  /// hash command with wrong length
  C2XSEC_DPK_VSOH_WRONG_LENGTH            = -11012,
  /// ECDSA accelerator timeout during verify signature of hash operation
  /// for NIST256 curve ID
  C2XSEC_NIST256_VSOH_TIMEOUT             = -11013,
  /// ECDSA accelerator timeout during decompress public key and verify
  /// signature of hash operation for NIST256 curve ID
  C2XSEC_NIST256_DPK_VSOH_TIMEOUT         = -11014,
  /// ECDSA accelerator timeout during decompress public key operation
  /// for NIST256 curve ID
  C2XSEC_NIST256_DPK_TIMEOUT              = -11015,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for NIST256 curve ID
  C2XSEC_NIST256_REPK_TIMEOUT             = -11016,
  /// ECDSA accelerator timeout during verify signature of hash operation
  /// for BP256R1 curve ID
  C2XSEC_BP256R1_VSOH_TIMEOUT             = -11017,
  /// ECDSA accelerator timeout during decompress public key and verify
  /// signature of hash operation for BP256R1 curve ID
  C2XSEC_BP256R1_DPK_VSOH_TIMEOUT         = -11018,
  /// ECDSA accelerator timeout during decompress public key operation
  /// for BP256R1 curve ID
  C2XSEC_BP256R1_DPK_TIMEOUT              = -11019,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for BP256R1 curve ID
  C2XSEC_BP256R1_REPK_TIMEOUT             = -11020,
  /// ECDSA accelerator timeout during verify signature of hash operation
  /// for BP384R1 curve ID
  C2XSEC_BP384R1_VSOH_TIMEOUT             = -11021,
  /// ECDSA accelerator timeout during decompress public key and verify
  /// signature of hash operation for BP384R1 curve ID
  C2XSEC_BP384R1_DPK_VSOH_TIMEOUT         = -11022,
  /// ECDSA accelerator timeout during decompress public key operation
  /// for BP384R1 curve ID
  C2XSEC_BP384R1_DPK_TIMEOUT              = -11023,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for BP384R1 curve ID
  C2XSEC_BP384R1_REPK_TIMEOUT             = -11024,
  /// ECDSA accelerator timeout during verify signature of hash (fail) self
  /// test operation for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_VSOHF_TIMEOUT   = -11025,
  /// ECDSA accelerator verify signature of hash (fail) self test result
  /// mismatch for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_VSOHF_MISMATCH  = -11026,
  /// ECDSA accelerator timeout during verify signature of hash (pass) self
  /// test operation for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_VSOHP_TIMEOUT   = -11027,
  /// ECDSA accelerator verify signature of hash (pass) self test result
  /// mismatch for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_VSOHP_MISMATCH  = -11028,
  /// ECDSA accelerator timeout during decompress public key self test operation
  /// for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_DPK_TIMEOUT     = -11029,
  /// ECDSA accelerator decompress public key self test result mismatch
  /// for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_DPK_MISMATCH    = -11030,
  /// ECDSA accelerator timeout during reconstruct ecc public key operation
  /// for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_REPK_TIMEOUT    = -11031,
  /// ECDSA accelerator reconstruct ECC public key self test result mismatch
  /// for NIST256 curve ID
  C2XSEC_NIST256_SELFTEST_REPK_MISMATCH   = -11032,
  /// C2XSec module detected internal memory corruption
  C2XSEC_MEMORY_CORRUPTION_1              = -11033,
  /// C2XSec module detected internal memory corruption
  C2XSEC_MEMORY_CORRUPTION_2              = -11034,
  /// C2XSec module detected internal memory corruption
  C2XSEC_MEMORY_CORRUPTION_3              = -11035,
  /// C2XSec module detected internal memory corruption
  C2XSEC_MEMORY_CORRUPTION_4              = -11036,
  /// Too many invalid 1PPS events
  INVALID_1PPS_EVENT                      = -11100,
  /// Received invalid API Version length
  INVALID_APIVERSION_LENGTH               = -11200,
  /// Received invalid Tx Packet length
  INVALID_TXPACKET_LENGTH                 = -11201,
  /// Radio config message length invalid
  INVALID_RADIOCONFIG_LENGTH              = -11202,
  /// Received invalid Flush Queue length
  INVALID_FLUSHQ_LENGTH                   = -11203,
  /// Invalid input parameter value for Cmd of tMKxSetTSF
  INVALID_SET_TSF_LENGTH                  = -11204,
  /// Received invalid GetTSF length
  INVALID_GET_TSF_LENGTH                  = -11205,
  /// Debug message length invalid
  INVALID_DEBUGMSG_LENGTH                 = -11206,
  /// Received Calibration command with invalid length
  INVALID_CALIBRATION_LENGTH              = -11207,
  /// Received Set Temperature command with invalid length
  INVALID_TEMP_LENGTH                     = -11208,
  /// Received AuxADC Configuration command with invalid length
  INVALID_AUXADCCFG_LENGTH                = -11209,
  /// Received LOG command with invalid length
  INVALID_LOG_LENGTH                      = -11210,
  /// Received GPIO command with invalid length
  INVALID_GPIO_LENGTH                     = -11211,
  /// Received Reset command with invalid length
  INVALID_RESET_LENGTH                    = -11212,
  /// Received Fault command with invalid length
  INVALID_FAULT_LENGTH                    = -11213,
  /// SDIO interface detected an SDIO data transfer error
  SDIO_ERROR_CALLBACK                     = -11300,
  /// Could not write to SDIO interface
  SDIO_WRITE_FAILED                       = -11301,
  /// SDIO interface upload callback watchdog triggered
  SDIO_UPLOAD_TIMEOUT                     = -11302,
  /// SDIO upload queue out of sync with upload request
  SDIO_QUEUE_SYNC_FAILURE                 = -11303,
  /// Radio config received at DSP with invalid radio mode
  DSP_INVALID_RADIO_MODE                  = -11400,
  /// Received invalid SetTSF command at DSP
  DSP_SET_TSF_CMD_INVALID                 = -11401,
  /// DSP Failed to boot
  DSP_INIT_WATCHDOG                       = -11402,
  /// DSP declared that ARM failed to initialise the Rx packet FIFO
  DSP_RXMAC_INIT_WATCHDOG                 = -11403,
  /// Ethernet configuration failed
  ETH_CONFIG_FAILED                       = -11500,
  /// Ethernet driver initialisation failed
  ETH_DRV_INIT_FAILED                     = -11501,
  /// Ethernet driver configuration failed
  ETH_DRV_CONFIG_FAILED                   = -11502,
  /// Ethernet ARP initialisation failed
  ETH_ARP_INIT_FAILED                     = -11503,
  /// Ethernet ARP Resolve failed
  ETH_ARP_RESOLVE_FAILED                  = -11504,
  /// Ethernet socket failed to initialise
  ETH_SOCKET_INIT_FAILED                  = -11505,
  /// Ethernet failed to open the Tx socket to the host
  ETH_INVALID_TX_SOCKET                   = -11506,
  /// Ethernet failed to open the Rx socket to the host
  ETH_INVALID_RX_SOCKET                   = -11507,
  /// Ethernet initial UDP send failed
  ETH_INITIAL_SEND_FAILED                 = -11508,
  /// Ethernet UDP send failed
  ETH_UDP_SEND_FAILED                     = -11509,
  /// Ethernet Upload Callback Timeout
  ETH_UPLOAD_TIMEOUT                      = -11510,
  /// Core Self Test range invalid
  CST_RANGE_INVALID                       = -11600,
  /// Core Self Test failed
  CST_TEST_FAILED                         = -11601,
  /// DMA channel acquisiton for SPI driver failed
  SPI_DMA_ACQ_FAILED                      = -11700,
  /// SPI driver configuration failed
  SPI_CONFIG_FAILED                       = -11701,
  /// Initial SPI read/write failed
  SPI_INIT_RW_FAILED                      = -11702,
  /// SPI Data available timeout.  Host not responded after 100ms
  SPI_DAV_TIMEOUT                         = -11703,
  /// SPI Hardware Error Callback
  SPI_ERROR_CALLBACK                      = -11704,
  /// TxWMAC DMA channel acquisition failed
  TXWMAC_DMA_ACQ_FAILED                   = -11800,
  /// TxWMAC acquired DMA channel configuration failed
  TXWMAC_DMA_SET_CHAN_CONFIG_FAILED       = -11801,
  /// Setting TxWMAC DMA complete callback listener failed
  TXWMAC_DMA_SET_LISTENER_FAILED          = -11802,
  /// TxWMAC DMA channel enabling failed
  TXWMAC_DMA_CHAN_ENABLED_FAILED          = -11803,
  /// TxWMAC DMA1 callback timeout (period = 100ms)
  TXWMAC_DMA1_TIMEOUT                     = -11804,
  /// TxWMAC DMA2 callback timeout (period = 100ms)
  TXWMAC_DMA2_TIMEOUT                     = -11805,
  /// TxWMAC DMA1 Invalid Callback Event
  TXWMAC_DMA1_INVALID_EVENT               = -11806,
  /// TxWMAC DMA2 Invalid Callback Event
  TXWMAC_DMA2_INVALID_EVENT               = -11807,
  /// DSP to ARM message send blocked (i.e. failed)
  DSP_MSG_SEND_BLOCKED                    = -11900,
  /// ARM to DSP command send blocked
  DSP_CMD_SEND_BLOCKED                    = -11901,
  /// TxMAC TxPacket parameters invalid
  TXMAC_TXPACKET_MALFORMED                = -12000,
  /// TxMAC TxPacket length parameter is too long
  TXMAC_TXPACKET_LENGTH_TOO_LONG          = -12001,
  /// TxMAC TxPacket Management frame length parameter is too long
  TXMAC_TXPACKET_MGMT_LENGTH_TOO_LONG     = -12002,
  /// TxPHY TxPacket internal pointer invalid
  TXPHY_TXPACKET_PTR_INVALID              = -12003,
  /// TxPHY TxPacket parameters invalid
  TXPHY_TXPACKET_MALFORMED                = -12004,
  /// Temperature I2C Ant 1 Sensor Failure
  TEMP_I2C_ANT1_FAILED                    = -12100,
  /// Temperature I2C Ant 2 Sensor Failure
  TEMP_I2C_ANT2_FAILED                    = -12101,
  /// Temperature Analog Ant 1 Sensor Failure
  TEMP_ANALOG_ANT1_FAILED                 = -12102,
  /// Temperature Analog Ant 2 Sensor Failure
  TEMP_ANALOG_ANT2_FAILED                 = -12103,
  /// Temperature Power Correction outside limits Ant1
  TEMP_POWERCAL_ANT1_INVALID              = -12104,
  /// Temperature Power Correction outside limits Ant2
  TEMP_POWERCAL_ANT2_INVALID              = -12105,
  /// TxPHY SF Encode failure
  TX_SFENC_FAILED                         = -12200,
  /// TxPHY Payload Encode failure
  TX_PAYLOADENC_FAILED                    = -12201,
  /// Tx Power Correction outside limits Ant1
  TX_POWERCAL_ANT1_INVALID                = -12202,
  /// Tx Power Correction outside limits Ant2
  TX_POWERCAL_ANT2_INVALID                = -12203,
  /// Tx Cyclic Shift Offset Out Of Bounds
  TX_CYCLICSHIFT_INVALID                  = -12204,
  /// Rx Orbit RxSF failure
  RX_RXSF_FAILED                          = -12300,
  /// Rx Orbit RxReDecode failure
  RX_RXREDECODE_FAILED                    = -12301,
  /// Rx AGC Unfreeze failure
  RX_AGCUNFREEZE_TIMEOUT                  = -12302,
  /// Rx Coarse Timing failure
  RX_COARSETIMING_FAILURE                 = -12303,
  /// Rx Invalid Antenna during configuration
  RX_START_INVALID_ANT                    = -12304,
  /// Tx-Rx RF Loopback signal field decode failure (doesn't match expected)
  TXRXLOOPBACK_DECODE_FAILED              = -12400,
  /// Tx-RX RF Loopback Start_RxReDecode failure
  TXRXLOOPBACK_RXREDECODE_FAILED          = -12401,
  /// Tx-RX RF Loopback RxSignalField failure
  TXRXLOOPBACK_RXSF_FAILED                = -12402,
  /// Tx-RX RF Loopback Coarse Timing failure
  TXRXLOOPBACK_COARSETIME_FAILED          = -12403,
  /// Calibration of the TRX failure
  RFE_TIMEOUT_CALTRX                      = -12500,
  /// Calibration NewRadioConfig failure
  RFE_TIMEOUT_NEWRADIOCONFIG              = -12501,
  /// ConfigManager Init failure
  RFE_TIMEOUT_CONFIGINIT                  = -12502,
  /// Calibration GPIO update failure
  RFE_TIMEOUT_GPIOPINUPDATE               = -12503,
  /// Register Write RFE falure
  RFE_TIMEOUT_REGISTERWRITE               = -12504,
  /// Overflow of the upload to the LLC of MKXIF_APIVERSION message
  LLC_UPLOAD_OVERFLOW_APIVERSION          = -12600,
  /// Overflow of the upload to the LLC of MKXIF_TXPACKET message
  LLC_UPLOAD_OVERFLOW_TXPACKET            = -12601,
  /// Overflow of the upload to the LLC of MKXIF_GPIO buffer full message
  LLC_UPLOAD_OVERFLOW_GPIO                = -12602,
  /// Overflow of the upload to the LLC of MKXIF_LOOPBACK message
  LLC_UPLOAD_OVERFLOW_LOOPBACK            = -12603,
  /// Overflow of the upload to the LLC of MKXIF_FAULT message
  LLC_UPLOAD_OVERFLOW_FAULT               = -12604,
  /// Overflow of the upload to the LLC of MKXIF_DEBUG Compensator message
  LlcUploadOverflowCompensator         = -12605,
  /// Overflow of the upload to the LLC of MKXIF_CALIBRATION message
  LLC_UPLOAD_OVERFLOW_CALIBRATION         = -12606,
  /// Compensator Processing Timeout
  COMPENSATOR_TIMEOUT                     = -12700,
  /// Compensator CRC Failure
  COMPENSATOR_CRC_FAILURE                 = -12701,
  /// TX Power Correction outside limits Ant1
  COMPENSATOR_POWERCAL_ANT1_INVALID       = -12702,
  /// TX Power Correction outside limits Ant2
  COMPENSATOR_POWERCAL_ANT2_INVALID       = -12703,
  /// No data is being received from the Compensator
  COMPENSATOR_NO_DATA_RECEIVED            = -12704,
  /// TimeSync Internal Failure
  TIMESYNC_INTERNAL_FAILURE               = -12800,
  /// RxWMAC Received Corrupted Packet
  RXWMAC_CORRUPT_PACKET                   = -12900,
  /// ECC Double bit overflow error ARM IMEM
  FSM_MEM_ECC_DOUBLE_OVERFLOW_ARMIMEM     = -13000,
  /// ECC Double bit error ARM IMEM
  FSM_MEM_ECC_DOUBLE_ARMIMEM              = -13001,
  /// ECC Double bit overflow error ARM DMEM
  FSM_MEM_ECC_DOUBLE_OVERFLOW_ARMDMEM     = -13002,
  /// ECC Double bit error ARM DMEM
  FSM_MEM_ECC_DOUBLE_ARMDMEM              = -13003,
  /// ECC Double bit overflow error ECDSA
  FSM_MEM_ECC_DOUBLE_OVERFLOW_ECDSA       = -13004,
  /// ECC Double bit error error ECDSA
  FSM_MEM_ECC_DOUBLE_ECDSA                = -13005,
  /// Parity overflow error SYSMEM
  FSM_MEM_PARITY_OVERFLOW_SYSMEM          = -13006,
  /// Parity error SYSMEM
  FSM_MEM_PARITY_SYSMEM                   = -13007,
  /// Parity overflow error EMACTX
  FSM_MEM_PARITY_OVERFLOW_EMACTX          = -13008,
  /// Parity error EMACTX
  FSM_MEM_PARITY_EMACTX                   = -13009,
  /// Parity overflow error EMACRX
  FSM_MEM_PARITY_OVERFLOW_EMACRX          = -13010,
  /// Parity error EMACRX
  FSM_MEM_PARITY_EMACRX                   = -13011,
  /// Parity overflow error SDIOSRAM
  FSM_MEM_PARITY_OVERFLOW_SDIOSRAM        = -13012,
  /// Parity error SDIOSRAM
  FSM_MEM_PARITY_SDIOSRAM                 = -13013,
  /// Parity overflow error SDIOCISSRAM
  FSM_MEM_PARITY_OVERFLOW_SDIOCISSRAM     = -13014,
  /// Parity error SDIOCISSRAM
  FSM_MEM_PARITY_SDIOCISSRAM              = -13015,
  /// Parity overflow error ECDSA CRYPTO0
  FSM_MEM_PARITY_OVERFLOW_CRYPTO0         = -13016,
  /// Parity error ECDSA CRYPTO0
  FSM_MEM_PARITY_CRYPTO0                  = -13017,
  /// Parity overflow error ECDSA CRYPTO1
  FSM_MEM_PARITY_OVERFLOW_CRYPTO1         = -13018,
  /// Parity error ECDSA CRYPTO1
  FSM_MEM_PARITY_CRYPTO1                  = -13019,
  /// ECC Double bit overflow error BBEIRAM0
  FSM_MEM_ECC_DOUBLE_OVERFLOW_BBEIRAM0    = -13020,
  /// ECC Double bit error BBEIRAM0
  FSM_MEM_ECC_DOUBLE_BBEIRAM0             = -13021,
  /// ECC Double bit overflow error BBEIRAM1
  FSM_MEM_ECC_DOUBLE_OVERFLOW_BBEIRAM1    = -13022,
  /// ECC Double bit error BBEIRAM1
  FSM_MEM_ECC_DOUBLE_BBEIRAM1             = -13023,
  /// Parity overflow error BBEDRAM00
  FSM_MEM_PARITY_OVERFLOW_BBEDRAM00       = -13024,
  /// Parity error BBEDRAM00
  FSM_MEM_PARITY_BBEDRAM00                = -13025,
  /// Parity overflow error BBEDRAM01
  FSM_MEM_PARITY_OVERFLOW_BBEDRAM01       = -13026,
  /// Parity error BBEDRAM01
  FSM_MEM_PARITY_BBEDRAM01                = -13027,
  /// Parity overflow error BBEDRAM02
  FSM_MEM_PARITY_OVERFLOW_BBEDRAM02       = -13028,
  /// Parity error BBEDRAM02
  FSM_MEM_PARITY_BBEDRAM02                = -13029,
  /// Parity overflow error BBEDRAM03
  FSM_MEM_PARITY_OVERFLOW_BBEDRAM03       = -13030,
  /// Parity error BBEDRAM03
  FSM_MEM_PARITY_BBEDRAM03                = -13031,
  /// Parity overflow error BBEDRAM10
  FSM_MEM_PARITY_OVERFLOW_BBEDRAM10       = -13032,
  /// Parity error BBEDRAM10
  FSM_MEM_PARITY_BBEDRAM10                = -13033,
  /// Parity overflow error BBEDRAM11
  FSM_MEM_PARITY_OVERFLOW_BBEDRAM11       = -13034,
  /// Parity error BBEDRAM11
  FSM_MEM_PARITY_BBEDRAM11                = -13035,
  /// Parity overflow error ORBITSP0
  FSM_MEM_PARITY_OVERFLOW_ORBITSP0        = -13036,
  /// Parity error ORBITSP0
  FSM_MEM_PARITY_ORBITSP0                 = -13037,
  /// Parity overflow error ORBITSP1
  FSM_MEM_PARITY_OVERFLOW_ORBITSP1        = -13038,
  /// Parity error ORBITSP1
  FSM_MEM_PARITY_ORBITSP1                 = -13039,
  /// Parity overflow error ORBITSP2
  FSM_MEM_PARITY_OVERFLOW_ORBITSP2        = -13040,
  /// Parity error ORBITSP2
  FSM_MEM_PARITY_ORBITSP2                 = -13041,
  /// Parity overflow error ORBITSP3
  FSM_MEM_PARITY_OVERFLOW_ORBITSP3        = -13042,
  /// Parity error ORBITSP3
  FSM_MEM_PARITY_ORBITSP3                 = -13043,
  /// Parity overflow error ORBITDP0
  FSM_MEM_PARITY_OVERFLOW_ORBITDP0        = -13044,
  /// Parity error ORBITDP0
  FSM_MEM_PARITY_ORBITDP0                 = -13045,
  /// Parity overflow error ORBITDP1
  FSM_MEM_PARITY_OVERFLOW_ORBITDP1        = -13046,
  /// Parity error ORBITDP1
  FSM_MEM_PARITY_ORBITDP1                 = -13047,
  /// ECC Double bit overflow error X2
  FSM_MEM_ECC_DOUBLE_OVERFLOW_X2          = -13048,
  /// ECC Double bit error X2
  FSM_MEM_ECC_DOUBLE_X2                   = -13049,
  /// Parity overflow error X2DMEM0
  FSM_MEM_PARITY_OVERFLOW_X2DMEM0         = -13050,
  /// Parity error X2DMEM0
  FSM_MEM_PARITY_X2DMEM0                  = -13051,
  /// Parity overflow error X2DMEM1
  FSM_MEM_PARITY_OVERFLOW_X2DMEM1         = -13052,
  /// Parity error X2DMEM1
  FSM_MEM_PARITY_X2DMEM1                  = -13053,
  /// ECC single bit overflow error ARMIMEM
  FSM_MEM_ECC_SINGLE_OVERFLOW_ARMIMEM     = -13070,
  /// ECC single bit error ARMIMEM
  FSM_MEM_ECC_SINGLE_ARMIMEM              = -13071,
  /// ECC single bit overflow error ARMDMEM
  FSM_MEM_ECC_SINGLE_OVERFLOW_ARMDMEM     = -13072,
  /// ECC single bit error ARMDMEM
  FSM_MEM_ECC_SINGLE_ARMDMEM              = -13073,
  /// ECC single bit overflow error ECDSA
  FSM_MEM_ECC_SINGLE_OVERFLOW_ECDSA       = -13074,
  /// ECC single bit error ECDSA
  FSM_MEM_ECC_SINGLE_ECDSA                = -13075,
  /// ECC single bit overflow error BBEIRAM0
  FSM_MEM_ECC_SINGLE_OVERFLOW_BBEIRAM0    = -13076,
  /// ECC single bit error BBEIRAM0
  FSM_MEM_ECC_SINGLE_BBEIRAM0             = -13077,
  /// ECC single bit overflow error BBEIRAM1
  FSM_MEM_ECC_SINGLE_OVERFLOW_BBEIRAM1    = -13078,
  /// ECC single bit error BBEIRAM1
  FSM_MEM_ECC_SINGLE_BBEIRAM1             = -13079,
  /// ECC single bit overflow error X2
  FSM_MEM_ECC_SINGLE_OVERFLOW_X2          = -13080,
  /// ECC single bit error X2
  FSM_MEM_ECC_SINGLE_X2                   = -13081,
  /// BBE Write Response Error, Reserved address/Illegal write to BBE memory
  FSM_MEM_DSP_ILLEGAL_WRITE               = -13088,
  /// ARMWDT Interrupt Error
  FSM_ARM_WATCHDOG                        = -13089,
  /// MDMWDT Interrupt Error
  FSM_DSP_WATCHDOG                        = -13090,
  /// RFEWDT Interrupt Error
  FSM_X2_WATCHDOG                         = -13091,
  /// ARMPLL0 unlock Error (unused)
  FSM_ARM_PLL0_UNLOCK                     = -13092,
  /// ARMPLL1 unlock Error (unused)
  FSM_ARM_PLL1_UNLOCK                     = -13093,
  /// RFEPLL unlock Error (unused)
  FSM_X2_PLL_UNLOCK                       = -13094,
  /// Core self-test failure Exception Test Svc
  CST_EXCEPTION_TEST_SVC                  = -14000,
  /// Core self-test failure Exception Test Pendsv
  CST_EXCEPTION_TEST_PENDSV               = -14001,
  /// Core self-test failure Exception Test Sys tick
  CST_EXCEPTION_TEST_SYSTICK              = -14002,
  /// Core self-test failure Exception Hard Fault1
  CST_EXCEPTION_HARD_FAULT1               = -14003,
  /// Core self-test failure Exception Hard Fault2
  CST_EXCEPTION_HARD_FAULT2               = -14004,
  /// Core self-test failure Exception Usage Fault
  CST_EXCEPTION_USAGE_FAULT               = -14005,
  /// Core self-test failure Exception Mem Fault
  CST_EXCEPTION_MEM_FAULT                 = -14006,
  /// Core self-test failure Exception Bus Fault
  CST_EXCEPTION_BUS_FAULT                 = -14007,
  /// Core self-test failure Exception Test Nmihf
  CST_EXCEPTION_TEST_NMIHF                = -14008,
  /// Core self-test failure Exception Test Tail Chain
  CST_EXCEPTION_TEST_TAILCHAIN            = -14009,
  /// Core self-test failure Exception Test Masking
  CST_EXCEPTION_TEST_MASKING              = -14010,
  /// Core self-test failure Exception Test Handler Thread
  CST_EXCEPTION_TEST_HANDLER              = -14011,
  /// Core self-test failure Regbank Test4
  CST_REGBANK_TEST4                       = -14012,
  /// Core self-test failure ALU Test7
  CST_ALU_TEST7                           = -14013,
  /// Core self-test failure Branch Test3
  CST_BRANCH_TEST3                        = -14014,
  /// Core self-test failure Status Test3
  CST_STATUS_TEST3                        = -14015,
  /// Core self-test failure Regbank Test6
  CST_REGBANK_TEST6                       = -14016,
  /// Core self-test failure Fetch Test
  CST_FETCH_TEST                          = -14017,
  /// Core self-test failure Load store Test6
  CST_LOADSTORE_TEST6                     = -14018,
  /// Core self-test failure Load store Test1
  CST_LOADSTORE_TEST1                     = -14019,
  /// Core self-test failure Load store Test2
  CST_LOADSTORE_TEST2                     = -14020,
  /// Core self-test failure Load store Test3
  CST_LOADSTORE_TEST3                     = -14021,
  /// Core self-test failure Load store Test4
  CST_LOADSTORE_TEST4                     = -14022,
  /// Core self-test failure Load store Test5
  CST_LOADSTORE_TEST5                     = -14023,
  /// Core self-test failure Regbank Test1
  CST_REGBANK_TEST1                       = -14024,
  /// Core self-test failure Regbank Test2
  CST_REGBANK_TEST2                       = -14025,
  /// Core self-test failure Regbank Test3
  CST_REGBANK_TEST3                       = -14026,
  /// Core self-test failure Regbank Test5
  CST_REGBANK_TEST5                       = -14027,
  /// Core self-test failure ALU Test1
  CST_ALU_TEST1                           = -14028,
  /// Core self-test failure ALU Test2
  CST_ALU_TEST2                           = -14029,
  /// Core self-test failure ALU Test3
  CST_ALU_TEST3                           = -14030,
  /// Core self-test failure ALU Test4
  CST_ALU_TEST4                           = -14031,
  /// Core self-test failure ALU Test5
  CST_ALU_TEST5                           = -14032,
  /// Core self-test failure ALU Test6
  CST_ALU_TEST6                           = -14033,
  /// Core self-test failure Branch Test1
  CST_BRANCH_TEST1                        = -14034,
  /// Core self-test failure Status Test1
  CST_STATUS_TEST1                        = -14035,
  /// Core self-test failure MAC Test1
  CST_MAC_TEST1                           = -14036,
  /// Core self-test failure MAC Test2
  CST_MAC_TEST2                           = -14037,
  /// Core self-test failure Status Test2
  CST_STATUS_TEST2                        = -14038,
  /// Core self-test failure Branch Test2
  CST_BRANCH_TEST2                        = -14039,
  /// Peripheral self-test outclk SAFEREF failure
  PST_CGU_OUTCLK0_SAFEREF                 = -14100,
  /// Peripheral self-test outclk ARM failure
  PST_CGU_OUTCLK1_ARM                     = -14101,
  /// Peripheral self-test outclk HSPI failure
  PST_CGU_OUTCLK2_HSPI                    = -14102,
  /// Peripheral self-test outclk AES failure
  PST_CGU_OUTCLK3_AES                     = -14103,
  /// Peripheral self-test outclk BA414EP failure
  PST_CGU_OUTCLK4_BA414EP                 = -14104,
  /// Peripheral self-test outclk SYSAPB failure
  PST_CGU_OUTCLK5_SYSAPB                  = -14105,
  /// Peripheral self-test outclk WDT failure
  PST_CGU_OUTCLK6_WDT                     = -14106,
  /// Peripheral self-test outclk PERIAPB failure
  PST_CGU_OUTCLK7_PERIAPB                 = -14107,
  /// Peripheral self-test outclk I2C failure
  PST_CGU_OUTCLK8_I2C                     = -14108,
  /// Peripheral self-test outclk UART failure
  PST_CGU_OUTCLK9_UART                    = -14109,
  /// Peripheral self-test outclk QSPI failure
  PST_CGU_OUTCLK10_QSPI                   = -14110,
  /// Peripheral self-test outclk BBE16 failure
  PST_CGU_OUTCLK11_BBE16                  = -14111,
  /// Peripheral self-test outclk TIMER failure
  PST_CGU_OUTCLK12_TIMER                  = -14112,
  /// Peripheral self-test outclk RMII failure
  PST_CGU_OUTCLK13_RMII                   = -14113,
  /// Peripheral self-test outclk RMIIRX failure
  PST_CGU_OUTCLK14_RMIIRX                 = -14114,
  /// Peripheral self-test outclk RMIITX failure
  PST_CGU_OUTCLK15_RGMIITX                = -14115,
  /// Peripheral self-test outclk REF CLK1 failure
  PST_CGU_OUTCLK16_REFCLK1                = -14116,
  /// Peripheral self-test outclk REF CLK2 failure
  PST_CGU_OUTCLK17_REFCLK2                = -14117,
  /// Peripheral self-test outclk WRCK failure
  PST_CGU_OUTCLK18_WRCK                   = -14118,
  /// Peripheral self-test failure Bus interconnect AHB2APB SYS
  PST_BUS_SYS                             = -14119,
  /// Peripheral self-test failure Bus interconnect AHB2VPBT ARM Timers
  PST_BUS_ARM_TIMERS                      = -14120,
  /// Peripheral self-test failure Bus interconnect AHB2VPBT RFE Timer
  PST_BUS_RFE_TIMER                       = -14121,
  /// Peripheral self-test failure Bus interconnect ORBIT State CRC
  PST_BUS_ORBIT_STATE_CRC                 = -14122,
  /// Peripheral self-test failure Chip Infra RGU
  PST_CHIP_INFRA_RGU                      = -14123,
  /// Peripheral self-test failure Chip Infra CREG
  PST_CHIP_INFRA_CREG                     = -14124,
  /// Peripheral self-test failure Chip Infra SCU Bank 2
  PST_CHIP_INFRA_SCU_BANK2                = -14125,
  /// Peripheral self-test failure Chip Infra SCU Bank 3
  PST_CHIP_INFRA_SCU_BANK3                = -14126,
  /// Peripheral self-test failure Chip Infra ARM Timers
  PST_CHIP_INFRA_ARM_TIMERS               = -14127,
  /// Peripheral self-test failure Chip Infra ARM Watchdog
  PST_CHIP_INFRA_ARM_WDT                  = -14128,
  /// Peripheral self-test failure Chip Infra DSP Watchdog
  PST_CHIP_INFRA_DSP_WDT                  = -14129,
  /// Peripheral self-test failure Peripheral Infra UART1
  PST_PERIPH_INFRA_UART1                  = -14132,
  /// Peripheral self-test failure Peripheral Infra UART2
  PST_PERIPH_INFRA_UART2                  = -14133,
  /// Peripheral self-test failure Peripheral Infra UART3
  PST_PERIPH_INFRA_UART3                  = -14134,
  /// Peripheral self-test failure Peripheral Infra UART4
  PST_PERIPH_INFRA_UART4                  = -14135,
  /// Peripheral self-test failure Peripheral Infra QSPI
  PST_PERIPH_INFRA_QSPI                   = -14136,
  /// Peripheral self-test failure Peripheral Infra I2C
  PST_PERIPH_INFRA_I2C                    = -14137,
  /// Peripheral self-test failure Peripheral Infra I2C Internal Regs
  PST_PERIPH_INFRA_I2CINT                 = -14138,
  /// Peripheral self-test failure Peripheral Infra GPIO Toggle
  PST_PERIPH_INFRA_GPIO_TOGGLE            = -14139,
  /// Peripheral self-test failure Peripheral Infra GPIO Loopback
  PST_PERIPH_INFRA_GPIO_LOOPBACK          = -14140,
  /// Peripheral self-test failure DMA
  PST_DMA                                 = -14141,
  /// Peripheral self-test failure ECDSA
  PST_ECDSA                               = -14142,
  /// Peripheral self-test failure Verify OTP
  PST_VERIFY_OTP                          = -14143,
  /// Peripheral self-test failure OTP Integrity NXP bank
  PST_OTP_INTEGRITY_NXP                   = -14144,
  /// Peripheral self-test failure OTP Integrity Customer bank
  PST_OTP_INTEGRITY_CUSTOMER              = -14145,
  /// PST clock test requested is out of range
  PST_CGU_CLOCKS_OUTOFRANGE               = -14200,
  /// PST clocks test config is invalid (0/null)
  PST_CGU_CLOCKS_INVALIDCONFIG            = -14201,
  /// PST Orbit failure for MCS0
  PST_ORBIT_FAILURE_MCS0                  = -14300,
  /// PST Orbit failure for MCS1
  PST_ORBIT_FAILURE_MCS1                  = -14301,
  /// PST Orbit failure for MCS2
  PST_ORBIT_FAILURE_MCS2                  = -14302,
  /// PST Orbit failure for MCS3
  PST_ORBIT_FAILURE_MCS3                  = -14303,
  /// PST Orbit failure for MCS4
  PST_ORBIT_FAILURE_MCS4                  = -14304,
  /// PST Orbit failure for MCS5
  PST_ORBIT_FAILURE_MCS5                  = -14305,
  /// PST Orbit failure for MCS6
  PST_ORBIT_FAILURE_MCS6                  = -14306,
  /// PST Orbit failure for MCS7
  PST_ORBIT_FAILURE_MCS7                  = -14307,
  // MBIST status errors
  /// Memory self-test was completed but test failed for some mem ring(s)
  MBIST_COMPLETED_FAILED                  = -14400,
  /// Memory self-test was not completed (aborted), thus failed
  MBIST_NOT_COMPLETED_FAILED              = -14401,
  // Boot status errors
  /// Boot status PBL to SBL booting failure
  BOOT_STATUS_BOOT_FAILURE                = -14500,
  /// Boot status PBL to SBL Read over i/f failure
  BOOT_STATUS_READ_FAILURE                = -14501,
  /// Boot status PBL to SBL phase Authentication failure
  BOOT_STATUS_AUTH_FAILURE                = -14502,
  /// Boot status PBL to SBL phase ID verification failure
  BOOT_STATUS_ID_VERF_FAILURE             = -14503,
  /// Boot status PBL to SBL phase BSH not found failure
  BOOT_STATUS_BSH_NOT_FOUND               = -14504,
  /// Boot status PBL to SBL phase BSH ended unexpected failure
  BOOT_STATUS_BSH_ENDED_FAILURE           = -14505,
  /// Boot status PBL to SBL phase invalid target address failure
  BOOT_STATUS_INVALID_TARGET_ADDR         = -14506,
  /// Boot status PBL to SBL phase invalid boot command
  BOOT_STATUS_INVALID_CMD                 = -14507,
  /// Boot status PBL to SBL phase invalid boot mode
  BOOT_STATUS_INVALID_BOOT_MODE           = -14508,
  /// Boot status PBL to SBL phase flash invalid address
  BOOT_STATUS_FLASH_INVALID_ADDR          = -14509,
  /// Boot status PBL to SBL phase decryption failure
  BOOT_STATUS_DECRYPTION_FAILURE          = -14510,
  /// Boot status PBL to SBL phase security init failure
  BOOT_STATUS_SECURITY_INIT_FAILURE       = -14511,
  /// Boot status PBL to SBL phase security OTP read failure
  BOOT_STATUS_SECURITY_OTP_READ_FAILURE   = -14512,
  /// Boot status PBL to SBL phase security config mismatch failure
  BOOT_STATUS_SECURITY_CONFIG_MISMATCH    = -14513,
  /// Boot status PBL to SBL phase CRC check failure
  BOOT_STATUS_CRC_CHECK_FAILURE           = -14514,
  /// Boot status PBL to SBL phase chunk id verification failure
  BOOT_STATUS_CHUNK_ID_VERF_FAILURE       = -14515,
  /// Boot status PBL to SBL phase image format mismatch failure
  BOOT_STATUS_IMG_FORMAT_MISMATCH         = -14516,
  /// Boot status PBL to SBL phase public key verification failure
  BOOT_STATUS_PUB_KEY_VERF_FAILURE        = -14517,
  /// Boot status PBL to SBL phase customer OTP not programmed failure
  BOOT_STATUS_CUSTOMER_OTP_NOT_PROG       = -14518,
  /// Boot status PBL to SBL phase Flash init failure
  BOOT_STATUS_FLASH_INIT_FAILURE          = -14519,
  /// Invalid input parameter value for RadioID of tMKxTxPacket
  INVALIDINPUT_TXPKT_RADIOID              = -15000,
  /// Invalid input parameter value for ChannelID of tMKxTxPacket
  INVALIDINPUT_TXPKT_CHANNELID            = -15001,
  /// Invalid input parameter value for TxAntenna of tMKxTxPacket
  INVALIDINPUT_TXPKT_TXANT                = -15002,
  /// Invalid input parameter value for MCS of tMKxTxPacket
  INVALIDINPUT_TXPKT_MCS                  = -15003,
  /// Invalid input parameter value for TxPower of tMKxTxPacket
  INVALIDINPUT_TXPKT_TXPOWER              = -15004,
  /// Invalid input parameter value for TxFrameLength of tMKxTxPacket
  INVALIDINPUT_TXPKT_TXFRAMELENGTH        = -15005,
  /// Invalid input parameter value for Cmd of tMKxSetTSF
  INVALIDINPUT_SETTSF_CMD                 = -15100,
  /// Invalid input parameter value for UTC of tMKxSetTSF
  INVALIDINPUT_SETTSF_UTC                 = -15101,
  /// Invalid input parameter value for TSF of tMKxSetTSF
  INVALIDINPUT_SETTSF_TSF                 = -15102,
  /// Invalid input parameter value for Mode of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_MODE              = -15200,
  /// Invalid input parameter value for ChannelFreq of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_CHANNELFREQ       = -15201,
  /// Invalid input parameter value for Bandwidth of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_BW                = -15202,
  /// Invalid input parameter value for TxAntenna of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_TXANT             = -15203,
  /// Invalid input parameter value for RxAntenna of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_RXANT             = -15204,
  /// Invalid input parameter value for DefaultMCS of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_DEFAULTMCS        = -15205,
  /// Invalid input parameter value for DefaultTxPower of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_DEFAULTTXPOWER    = -15206,
  /// Invalid input parameter value for DualTxControl of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_DUALTXCTRL        = -15207,
  /// Invalid input parameter value for CSThreshold of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_CSTHRESH          = -15208,
  /// Invalid input parameter value for CBRThreshold of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_CBRTHRESH         = -15209,
  /// Invalid input parameter value for SlotTime of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_SLOTTIME          = -15210,
  /// Invalid input parameter value for DIFSTime of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_DIFSTIME          = -15211,
  /// Invalid input parameter value for SIFSTime of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_SIFSTIME          = -15212,
  /// Invalid input parameter value for EFISTime of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_EIFSTIME          = -15213,
  /// Invalid input parameter value for ShortRetryLimit of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_SHORTRETRY        = -15214,
  /// Invalid input parameter value for LongRetryLimit of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_LONGRETRY         = -15215,
  /// Invalid input parameter value for TxQueue.AIFS of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_AIFS              = -15216,
  /// Invalid input parameter value for TxQueue.CWMIN of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_CWMIN             = -15217,
  /// Invalid input parameter value for TxQueue.CWMAX of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_CWMAX             = -15218,
  /// Invalid input parameter value for TxQueue.TXOP of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_TXOP              = -15219,
  /// Invalid input parameter value for IntervalDuration of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_INTERVAL          = -15220,
  /// Invalid input parameter value for GuardDuration of tMKxRadioConfig
  INVALIDINPUT_RADIOCFG_GUARD             = -15221,
  /// Invalid input parameter value for RadioID of tMKxFlushQueue
  INVALIDINPUT_FLUSHQ_RADIOID             = -15300,
  /// Invalid input parameter value for ChannelID of tMKxFlushQueue
  INVALIDINPUT_FLUSHQ_CHANNELID           = -15301,
  /// Invalid input parameter value for TxQueue of tMKxFlushQueue
  INVALIDINPUT_FLUSHQ_TXQUEUE             = -15302,
  /// Invalid input parameter value for Version of tMKxCalibration
  INVALIDINPUT_CALIB_VERSION              = -15400,
  /// Invalid input parameter value for CompensatorSel of tMKxCalibration
  INVALIDINPUT_CALIB_COMPENSATORSEL       = -15401,
  /// INVALID INPUT parameter value for TxPowerCalMode of tMKxCalibration
  INVALIDINPUT_CALIB_TXPOWERCALMODE       = -15402,
  /// Invalid input parameter value for RSSICalMode of tMKxCalibration
  INVALIDINPUT_CALIB_RSSICALMODE          = -15403,
  /// Invalid input parameter value for CompensatorReturn of tMKxCalibration
  INVALIDINPUT_CALIB_COMPRETURN           = -15404,
  /// Invalid input parameter value Compensator.TxPowerThresh of tMKxCalibration
  INVALIDINPUT_CALIB_COMPPOWERTHRESH      = -15405,
  /// Invalid input parameter value for Compensator.Alpha of tMKxCalibration
  INVALIDINPUT_CALIB_COMPALPHA            = -15406,
  /// Invalid input parameter value for Compensator.Beta of tMKxCalibration
  INVALIDINPUT_CALIB_COMPBETA             = -15407,
  /// Invalid input parameters value PALNA.Alpha + PALNA.Beta != 256
  INVALIDINPUT_CALIB_COMPALPHABETA        = -15408,
  /// Invalid input parameter value for PALNA.TxPowerThresh of tMKxCalibration
  INVALIDINPUT_CALIB_PALNAPOWERTHRESH     = -15409,
  /// Invalid input parameter value for PALNA.Alpha of tMKxCalibration
  INVALIDINPUT_CALIB_PALNAALPHA           = -15410,
  /// Invalid input parameter value for PALNA.Beta of tMKxCalibration
  INVALIDINPUT_CALIB_PALNABETA            = -15411,
  /// Invalid input parameters value PALNA.Alpha + PALNA.Beta != 256
  INVALIDINPUT_CALIB_PALNAALPHABETA       = -15412,
  /// Invalid input parameter value for TxPowerExtraDrive of tMKxCalibration
  INVALIDINPUT_CALIB_EXTRADRIVE           = -15413,
  /// Invalid input parameter value for TxPowerLimitMaxPower of tMKxCalibration
  INVALIDINPUT_CALIB_LIMITMAXPOWER        = -15414,
  /// Invalid input parameter value for Temp SensorSource of tMKxCalibration
  INVALIDINPUT_CALIB_TEMPSENSOR           = -15415,
  /// Invalid input parameter value for I2CAddrSensor1 of tMKxCalibration
  INVALIDINPUT_CALIB_TEMPI2CADDRSENSOR1   = -15416,
  /// Invalid input parameter value for I2CAddrSensor2 of tMKxCalibration
  INVALIDINPUT_CALIB_TEMPI2CADDRSENSOR2   = -15417,
  /// Invalid input parameter value for PAEnableGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_PAENABLEGPIO         = -15418,
  /// Invalid input parameter value for LNAEnableGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_LNAENABLEGPIO        = -15419,
  /// Invalid input parameter value for RemotePAEnableGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_REMOTEPAGPIO         = -15420,
  /// Invalid input parameter value for C1GPIO of tMKxCalibration
  INVALIDINPUT_CALIB_C1GPIO               = -15421,
  /// Invalid input parameter value for TxClaimGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_TXCLAIMGPIO          = -15422,
  /// Invalid input parameter value for CompensatorEnableGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_COMPENGPIO           = -15423,
  /// Invalid input parameter value for Timing.PAEnableLNADisable
  INVALIDINPUT_CALIB_TIMINGPAEN           = -15424,
  /// Invalid input parameter value for Timing.BasebandStart of tMKxCalibration
  INVALIDINPUT_CALIB_TIMINGBBSTART        = -15425,
  /// Invalid input parameter value for Timing.AuxillaryADC of tMKxCalibration
  INVALIDINPUT_CALIB_TIMINGAUXADC         = -15426,
  /// Invalid input parameter value for Timing.RemotePADisable
  INVALIDINPUT_CALIB_TIMINGREMOTEPA       = -15427,
  /// Invalid input parameter value for Timing.PADisable of tMKxCalibration
  INVALIDINPUT_CALIB_TIMINGPADIS          = -15428,
  /// Invalid input parameter value for Timing.LNAEnable of tMKxCalibration
  INVALIDINPUT_CALIB_TIMINGLNAEN          = -15429,
  /// Invalid input parameter value for OnePPSGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_1PPSGPIO             = -15430,
  /// Invalid input parameter value for CCAGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_CCAGPIO              = -15431,
  /// Invalid input parameter value for TxActiveGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_TXACTIVEGPIO         = -15432,
  /// Invalid input parameter value for RxActiveGPIO of tMKxCalibration
  INVALIDINPUT_CALIB_RXACTIVEGPIO         = -15433,
  /// Invalid input parameter value for OtherRadioTxActiveGPIO
  INVALIDINPUT_CALIB_OTHERTXGPIO          = -15434,
  /// Invalid input parameter value for OtherRadioRxActiveGPIO
  INVALIDINPUT_CALIB_OTHERRXGPIO          = -15435,
  /// Invalid input parameter value for Ant1 ATemp.AuxADCInput (tMKxCalibration)
  INVALIDINPUT_CALIB_ATEMPANT1AUXADC      = -15436,
  /// Invalid input parameter value for Ant2 ATemp.AuxADCInput (tMKxCalibration)
  INVALIDINPUT_CALIB_ATEMPANT2AUXADC      = -15437,
  /// Invalid input parameter value for Temp.TempPAAnt1 of tMKxTemp
  INVALIDINPUT_TEMP_PAANT1                = -15500,
  /// Invalid input parameter value for Temp.TempPAAnt2 of tMKxTemp
  INVALIDINPUT_TEMP_PAANT2                = -15501,
  /// Invalid input parameter value for GPIO.Cmd of tMKxGPIO
  INVALIDINPUT_GPIO_CMD                   = -15600,
  /// Invalid input parameter value for GPIO.PinNumber of tMKxGPIO
  INVALIDINPUT_GPIO_PIN                   = -15601,
  /// Invalid input parameter value for GPIO.Value of tMKxGPIO
  INVALIDINPUT_GPIO_VALUE                 = -15602,
  /// Invalid input parameter value for Cmd of tMKxFault
  INVALIDINPUT_FAULT_CMD                  = -15700,
  /// Invalid input parameter value for CommandErrorCode of tMKxFault
  INVALIDINPUT_FAULT_CMDERRORCODE         = -15701,

  // Errors detected within the LLC kernel module
  /// USB interface device not present
  USB_DEVICE_NOT_PRESENT                  = -16100,
  /// The LLC kernel module encountered an invalid configuration of the SPI
  /// hardware while initialising the SPI interface
  SPI_DEVICE_NOT_PRESENT                  = -16200,
  /// An operation by the LLC kernel module on the SPI interface timed out
  /// (1 second)
  SPI_INTERFACE_TIMEOUT                   = -16201,
  /// The allocation by the LLC kernel module of a buffer to upload into,
  /// from the device failed
  SPI_BUFFER_ALLOCATION_FAILURE           = -16202,
  /// The queue used by the LLC kernel module for input transfers using the
  /// SPI interface was exhausted
  SPI_INPUT_QUEUE_EXHAUSTED               = -16203,
  /// An error was encountered by the LLC kernel module when examining the
  // contents of the output transfer queue used for SPI interface transfers
  SPI_OUTPUT_QUEUE_ERROR                  = -16204,
  /// An invalid transfer structure was encountered by the LLC kernel module
  /// when trying to perform a transfer on the SPI interface
  SPI_INVALID_TRANSFER_STRUCTURE          = -16205,
  /// An invalid output transfer structure was encountered by the the LLC
  /// kernel module when trying to perform a transfer on the SI interface
  SPI_INVALID_OUTPUT_CONTEXT              = -16206,
  /// The ring buffer used by the LLC kernel module for output transfers
  /// on the SPI interface was overrun
  SPI_BUFFER_OVERRUN                      = -16207,
  /// The LLC kernel module encountered a system error when requesting a
  /// transfer on the SPI interface
  SPI_SYSTEM_ERROR                        = -16208,
  /// A critical structure used by the LLC kernel module when performing a
  /// transfer on the SPI interface was invalid
  SPI_INVALID_CRITICAL_STRUCTURES         = -16209,
  /// The LLC kernel module encountered an invalid device ID when handling
  /// an interrupt from the SPI interface
  SPI_INVALID_DEVICE_ID                   = -16210,
  /// The corrupted structure associated with a transfer on the SPI interface
  /// was encountered by the LLC kernel module
  SPI_MEMORY_CORRUPTION                   = -16211,
  /// A memory allocation failure was encountered by the LLC kernel module
  /// when using the SPI interface
  SPI_MEMORY_ALLOCATION_FAILURE           = -16212,
  /// The LLC kernel module encountered invalid SPI hardware configuration
  /// information when attempting to initialise the SPI interface
  SPI_INIT_ERROR_DEVICE_NOT_PRESENT       = -16213,
  /// The LLC kernel module encountered already initialised SPI hardware
  /// when attempting to initialise the SPI interface
  SPI_INIT_ERROR_DEVICE_ALREADY_SETUP     = -16214,
  /// The LLC kernel module was unable to allocate Tx cache memory
  /// when attempting to initialise the SPI interface
  SPI_SYSTEM_CACHE_ALLOC_FAILURE          = -16215,
  /// The LLC kernel module encountered an initialisation failure of a
  /// list structure used with the SPI interface
  SPI_SYSTEM_LIST_INIT_ERROR              = -16216,
  /// The LLC kernel module encountered an allocation failure of a
  /// list structure used with the SPI interface
  SPI_SYSTEM_LIST_ITEM_ALLOC_ERROR        = -16217,
  /// The LLC kernel module encountered a failure of an operation on a
  /// list structure used with the SPI interface
  SPI_SYSTEM_LIST_ITEM_ADD_ERROR          = -16218,
  /// The LLC kernel module encountered a system error when requesting a
  /// pointer to the SPI interface bus master structure
  SPI_SYSTEM_BUS_TO_MASTER_ERROR          = -16219,
  /// The LLC kernel module SPI interface configuration was observed to be
  /// inconsistent with the system
  SPI_SYSTEM_INVALID_CHIPSELECT           = -16220,
  /// The LLC kernel module encountered a system error when requesting the
  /// SPI device to be used be added to the SPI bus during initialisation
  SPI_SYSTEM_ADD_DEVICE_ERROR             = -16221,
  /// The LLC kernel module encountered a system error when requesting
  /// access to the DAV pin used for interrupt based SPI operation
  SPI_SYSTEM_DAV_PIN_REQUEST_ERROR        = -16222,
  /// The LLC kernel module encountered a system error when requesting
  /// the system associate the DAV pin with an IRQ handling function
  SPI_SYSTEM_DAV_TO_IRQ_REQUEST_ERROR     = -16223,
  /// The LLC kernel module encountered an invalid SPI operating mode when
  /// initialising the SPI interface
  SPI_INVALID_SPI_MODE                    = -16224,
  /// The LLC kernel module encountered an SPI interrupt while the module
  /// was not in an enabled state
  SPI_INTERRUPT_BUT_NOT_ENABLED           = -16225,
  /// The LLC kernel module attempted to initialise the SDIO interface
  /// without it being required
  SDIO_DEVICE_NOT_REQUIRED                = -16300,
  /// An operation by the LLC kernel module on the SDIO interface timed out
  /// (1 second)
  SDIO_INTERFACE_TIMEOUT                  = -16301,
  /// The LLC kernel module encountered a failure when attempting to
  /// enable the SDIO interface interrupt essential for receving data
  SDIO_ENABLE_INTERRUPT_FAILURE           = -16303,
  /// The LLC kernel module encountered a failure when attempting to
  /// disable the SDIO interface interrupt used for receving data
  SDIO_DISABLE_INTERRUPT_FAILURE          = -16304,
  /// The LLC kernel module encountered a failure when attempting to clear
  /// the SDIO interface interrupt
  SDIO_CLEAR_INTERRUPT_FAILURE            = -16305,
  /// The LLC kernel module encountered a failure when attempting to write
  /// to the SDIO device
  SDIO_SYSTEM_WRITE_TO_DEVICE_FAILURE     = -16306,
  /// The LLC kernel module encountered a failure when attempting to read
  /// data from the SDIO device
  SDIO_SYSTEM_READ_FROM_DEVICE_FAILURE    = -16308,
  /// The LLC kernel module was unable to register the SDIO unable to
  /// register the driver with the system
  SDIO_SYSTEM_REGISTER_DRIVER_FAILURE     = -16309,
  /// The LLC kernel module encountered an initialisation failure of a
  /// list structure used with the SDIO interface
  SDIO_SYSTEM_LIST_INIT_ERROR             = -16310,
  /// The LLC kernel module encountered an allocation failure of a
  /// list structure used with the SDIO interface
  SDIO_SYSTEM_LIST_ITEM_ALLOC_ERROR       = -16311,
  /// The LLC kernel module encountered a failure of an operation on a
  /// list structure used with the SDIO interface
  SDIO_SYSTEM_LIST_ITEM_ADD_ERROR         = -16312,
  /// The LLC kernel module encountered a failure when attempting to
  /// enable the SDIO interface through the system
  SdioSystemFunctionEnableError       = -16313,
  /// The LLC kernel module encountered a failure when attempting to
  /// set the SDIO interface data transfer block size
  SDIO_SYSTEM_SET_BLOCK_SIZE_ERROR        = -16314,
  /// The LLC kernel module encountered a failure when attempting to
  /// read a byte from the SDIO device
  SDIO_SYSTEM_READ_BYTE_ERROR             = -16315,
  /// The LLC kernel module encountered a failure when attempting to
  /// write a byte to the SDIO device
  SDIO_SYSTEM_WRITE_BYTE_ERROR            = -16316,
  /// The corrupted structure associated with a transfer on the SDIO interface
  /// was encountered by the LLC kernel module
  SDIO_MEMORY_CORRUPTION                  = -16317,
  /// The LLC kernel module was asked to send data out on the SDIO interface
  /// with the module not being in an enabled state
  SDIO_OUT_NOT_ENABLED                    = -16318,
  /// The LLC kernel module was asked to receive data on the SDIO interface
  /// with the module not being in an enabled state
  SDIO_IN_NOT_ENABLED                     = -16319,
  /// The LLC kernel module attempted to use the SDIO interface but
  /// system pointer to the device structure was NULL
  SDIO_SYSTEM_FUNCTION_NOT_ENABLED        = -16320,
  /// The queue used by the LLC kernel module for input transfers using the
  /// SDIO interface was exhausted
  SDIO_INPUT_QUEUE_EXHAUSTED              = -16321,
  /// The LLC kernel module encountered a request to read zero bytes from
  /// the device over the SDIO interface
  SDIO_ZERO_UPLOAD_LENGTH                 = -16322,
  /// The LLC kernel module encountered a corrupted message that was read
  /// from the device over the SDIO interface
  SDIO_CORRUPTED_INPUT_PACKET             = -16323,
  /// A memory allocation failure was encountered by the LLC kernel module
  /// when using the SDIO interface
  SDIO_MEMORY_ALLOCATION_FAILURE          = -16324,
  /// The LLC kernel module encountered an invalid configuration of the
  /// Eth hardware while initialising the ETH interface
  ETH_DEVICE_NOT_PRESENT                  = -16400,
  /// The corrupted structure associated with a transfer on the Eth interface
  /// was encountered by the LLC kernel module
  ETH_MEMORY_CORRUPTION                   = -16401,
  /// The LLC kernel module encountered a corrupted message that was read
  /// from the device over the Eth interface
  ETH_CORRUPTED_INPUT_PACKET              = -16402,
  /// The LLC kernel module encountered a missing socket when attempting to
  /// use the Eth interface
  ETH_SOCKET_MISSING                      = -16403,
  /// The queue used by the LLC kernel module for input transfers using the
  /// Eth interface was exhausted
  ETH_INPUT_QUEUE_EXHAUSTED               = -16404,
  /// A memory allocation failure was encountered by the LLC kernel module
  /// when using the Eth interface
  ETH_MEMORY_ALLOCATION_FAILURE           = -16405,
  /// The LLC kernel module encountered an error when attempting to transmit
  /// data via the Eth interface
  ETH_SYSTEM_TX_ERROR                     = -16406,
  /// The LLC kernel module encountered an error when attempting to receive
  /// data via the Eth interface
  ETH_SYSTEM_RX_ERROR                     = -16407,
  /// The LLC kernel module encountered an error when attempting to create
  /// a socket during the initialsation of the the Eth interface
  ETH_SYSTEM_RX_SOCKET_ERROR              = -16408,
  /// The LLC kernel module encountered an error when attempting to bind to
  /// a socket during the initialsation of the the Eth interface
  ETH_SYSTEM_BIND_ERROR                   = -16409,
  /// The LLC kernel module encountered an error when attempting to set the
  /// scheduling of the socket receive thread during the initialsation of
  /// the the Eth interface
  ETH_SYSTEM_SET_SCHEDULER_ERROR          = -16410,
  /// The LLC kernel module encountered an initialisation failure of a
  /// list structure used with the Eth interface
  ETH_SYSTEM_LIST_INIT_ERROR              = -16411,
  /// The LLC kernel module encountered an allocation failure of a
  /// list structure used with the Eth interface
  EthSystemListItemAllocError        = -16412,
  /// The LLC kernel module encountered a failure of an operation on a
  /// list structure used with the Eth interface
  ETH_SYSTEM_LIST_ITEM_ADD_ERROR          = -16413,
  /// The LLC kernel module encountered an overflow error when transmitting
  /// data via the Eth interface
  EthSystemOverflowError               = -16414,
  /// An operation by the LLC kernel module on the Eth interface timed out
  /// (1 second)
  ETH_INTERFACE_TIMEOUT                   = -16415,
  /// The LLC kernel module was asked to send data out on the Eth interface
  /// with the module not being in an enabled state
  EthOutNotEnabled                     = -16416,
    }
}

/// A read/write wrapper around an NXP LLC Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    /// 2-octet Message type field of the NXP LLC Header.
    pub const TYPE: Field = 0..2;
    /// 2-octet Length of the message (including the header itself) field of the NXP LLC Header.
    pub const LEN: Field = 2..4;
    /// 2-octet Sequence Number field of the NXP LLC Header.
    pub const SEQ_NUM: Field = 4..6;
    /// 2-octet Reference Number field of the NXP LLC Header.
    pub const REF_NUM: Field = 6..8;
    /// 2-octet Reserved field of the NXP LLC Header.
    pub const RESERVED: Field = 8..10;
    /// 2-octet Return value field of the NXP LLC Header.
    pub const RET: Field = 10..12;
    /// Content following the NXP LLC Header.
    pub const CONTENT: Rest = 12..;
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with a NXP LLC Header structure.
    pub fn new_unchecked(buffer: T) -> Header<T> {
        Header { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        // Check if size is at it's bare minimum.
        if len < field::RET.end {
            return Err(Error);
        }

        let msg_len = self.msg_len();

        // Check message length content.
        if msg_len < field::RET.end {
            return Err(Error);
        }

        // Check packet is not truncated.
        if len < msg_len {
            return Err(Error);
        }

        Ok(())
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Message {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::TYPE]);
        Message::from(raw)
    }

    /// Return the message length field.
    pub fn msg_len(&self) -> usize {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LEN]).into()
    }

    /// Return the sequence number field.
    pub fn seq_num(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::SEQ_NUM])
    }

    /// Return the reference number field.
    pub fn ref_num(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::REF_NUM])
    }

    /// Return the return value field.
    pub fn ret(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::RET])
    }
}

/* impl<'a, T: AsRef<[u8]> + ?Sized> Header<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[HEADER_LEN..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the destination port. NXP LLC and B.
    #[inline]
    pub fn set_destination_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::DST_PORT], value);
    }

    /// Set the source port. NXP LLC only.
    #[inline]
    pub fn set_source_port(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::SRC_PORT], value);
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[HEADER_LEN..]
    }
}

/// A high-level representation of a NXP LLC header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    /// The destination port contained inside the NXP LLC header.
    pub dst_port: u16,
    /// The source port contained inside the NXP LLC header.
    pub src_port: u16,
}

impl Repr {
    /// Parse a NXP LLC Header and return a high-level representation.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(header: &Header<&T>) -> Result<Repr> {
        header.check_len()?;
        Ok(Repr {
            dst_port: header.destination_port(),
            src_port: header.source_port(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        HEADER_LEN
    }

    /// Emit a high-level representation into a NXP LLC Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, header: &mut Header<T>) {
        header.set_destination_port(self.dst_port);
        header.set_source_port(self.src_port);
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&'a T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => write!(f, "NXP LLC ({err})"),
        }
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NXP LLC dst={} src={}", self.dst_port, self.src_port)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Repr {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "NXP LLC dst={} src={}", self.dst_port, self.src_port);
    }
}

use crate::wire::pretty_print::{PrettyIndent, PrettyPrint};

impl<T: AsRef<[u8]>> PrettyPrint for Header<T> {
    fn pretty_print(
        buffer: &dyn AsRef<[u8]>,
        f: &mut fmt::Formatter,
        indent: &mut PrettyIndent,
    ) -> fmt::Result {
        match Header::new_checked(buffer) {
            Err(err) => write!(f, "{indent}({err})"),
            Ok(packet) => write!(f, "{indent}{packet}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A BTP-B Header
    static BYTES_HEADER: [u8; 4] = [0x7f, 0x4b, 0x3a, 0x98];

    #[test]
    fn test_check_len() {
        // less than 4 bytes
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_HEADER[..2]).check_len()
        );

        // valid
        assert_eq!(Ok(()), Header::new_unchecked(&BYTES_HEADER).check_len());
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        assert_eq!(header.destination_port(), 32587);
        assert_eq!(header.source_port(), 15000);
    }

    #[test]
    fn test_repr_parse_valid() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(
            repr,
            Repr {
                dst_port: 32587,
                src_port: 15000
            }
        );
    }

    #[test]
    fn test_repr_emit() {
        let repr = Repr {
            dst_port: 32587,
            src_port: 15000,
        };
        let mut bytes = [0u8; 4];
        let mut header = Header::new_unchecked(&mut bytes);
        repr.emit(&mut header);
        assert_eq!(header.into_inner(), &BYTES_HEADER);
    }

    #[test]
    fn test_buffer_len() {
        let header = Header::new_unchecked(&BYTES_HEADER);
        let repr = Repr::parse(&header).unwrap();
        assert_eq!(repr.buffer_len(), BYTES_HEADER.len());
    }
}
 */
