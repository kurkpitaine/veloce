use crate::wire::{Error, Result};
use byteorder::{ByteOrder, LittleEndian};

use self::{radio_config::RadioConfigRepr, rx_packet::RxPacketRepr, tx_packet::TxPacketRepr};

pub mod radio_config;
pub mod rx_packet;
pub mod tx_packet;

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
        InvalidMkxIfType                  = -256,
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
        /// Received MKXIF message with unexpected or invalid type
        InvalidMkxIfType2                      = -10000,
        /// Upload message type or length was corrupted
        HostUploadMsgCorrupted               = -10001,
        /// DSP fault asserted without an error code
        DspUnknown                             = -10002,
        /// Test fault condition reported by DSP, commanded by host message
        DspFaultTest                        = -10003,
        /// Test fault condition reported by ARM, commanded by host message
        ArmFaultTest                          = -10004,
        /// Attempted to access a radio that does not exist in the system
        RadiobUnsupported                      = -10005,
        /// Internal DSP to ARM Interrupt failure (DSP side)
        DspTestfaultFailed                    = -10006,
        /// Internal DSP to ARM Interrupt failure (ARM side)
        ArmTestfaultFailed                    = -10007,
        /// Exception occurred on the DSP
        DspException                           = -10008,
        /// Timeout (1s) waiting for DSP to be available to process RadioConfig msg
        RadioconfigTimeout                     = -10009,
        /// Error reading the one-time programmable (OTP) data
        OtpFailure                             = -10010,
        /// Attempted to retire a frame with queue index out of bounds
        TxqueueIndexOutOfBounds             = -10100,
        /// Attempted to retire a frame with a null QED
        TxqueueNullQed                        = -10101,
        /// Attempted to retire a frame with a null queue pointer
        TxqueueNullQueueptr                   = -10102,
        /// Attempted to retire a frame with a null TxPkt pointer
        TxqueueNullTxpkt                      = -10103,
        /// Attempted to flush txqueue but locked up
        TxqueueFlushWatchdog                  = -10104,
        /// Attempted to fail frame exchange on an inactive queue number
        TxqueueInactiveQueuenumFailfex       = -10105,
        /// UPL DMA lockup error where write pointer is not updated during tx
        TxUplDmaWrptrLockup                 = -10200,
        /// ARM received invalid ARMCmd type from the DSP
        InvalidArmCmd                         = -10300,
        /// DSP received an invalid command from the ARM
        InvalidDspCmd                         = -10301,
        /// Read or Write request when EEPROM was not detected on boot
        EepromNotPresent                      = -10400,
        /// Importing of calibration data failed due to EEPROM not being programmed
        EepromNotProgrammed                   = -10401,
        /// EEPROM sleep command timed out indicating internal ARM timer has stopped
        EepromSleepTimeout                    = -10402,
        /// EEPROM read timeout event from I2C driver
        EepromReadTimeout                     = -10403,
        /// EEPROM read failed event from I2C driver
        EepromReadFailed                      = -10404,
        /// EEPROM read incomplete where not all requested bytes were read
        EepromReadIncomplete                  = -10405,
        /// EEPROM read overflow where more bytes than requested were read
        EepromOverread                         = -10406,
        /// EEPROM I2C driver failed to set device address for read
        EepromReadSetDeviceAddrFailed      = -10407,
        /// EEPROM I2C write failed to set address for upcoming read
        EepromReadSetAddrFailed             = -10408,
        /// EEPROM write timeout event from I2C driver
        EepromWriteTimeout                    = -10409,
        /// EEPROM write failed event from I2C driver
        EepromWriteFailed                     = -10410,
        /// EEPROM write incomplete where not all requested bytes were written
        EepromWriteIncomplete                 = -10411,
        /// EEPROM overflow where more bytes were written than requested
        EepromOverwrite                        = -10412,
        /// EEPROM I2C driver failed to set device address for write
        EepromWriteSetDeviceAddrFailed     = -10413,
        /// Bank requested is out of range (Range 0 to 3)
        EepromInvalidBank                     = -10414,
        /// Magic number in EEPROM is incorrect for import
        EepromInvalidMagic                    = -10415,
        /// Version number in EEPROM is incorrect for import
        EepromInvalidVersion                  = -10416,
        /// Calculated CRC of EEPROM data did not match for import
        EepromInvalidCrc                      = -10417,
        /// Write to bank 1 attempted but bank locked as magic number has been set
        EepromBankLocked                      = -10418,
        /// Memory access request is outside of valid range
        InvalidMemoryRange                    = -10500,
        /// Capture timed out
        CaptureTimeout                         = -10600,
        /// Invalid TXPHY Register (Out of range)
        InvalidTxphyRegister                  = -10700,
        /// Invalid RXPHY Register (Out of range)
        InvalidRxphyRegister                  = -10701,
        /// Invalid CALIB Register (Out of range)
        InvalidCalibRegister                  = -10702,
        /// Invalid ARM Register (Out of range)
        InvalidArmRegister                    = -10703,
        /// Invalid RFE Register (Out of range)
        InvalidRfeRegister                    = -10704,
        /// Invalid EEPROM0 Register (Out of range)
        InvalidEeprom0Register                = -10705,
        /// Invalid EEPROM1 Register (Out of range)
        InvalidEeprom1Register                = -10706,
        /// Invalid EEPROM2 Register (Out of range)
        InvalidEeprom2Register                = -10707,
        /// Invalid Bank Read (Out of range)
        InvalidBankRead                       = -10708,
        /// Invalid Bank Write (Out of range)
        InvalidBankWrite                      = -10709,
        /// Invalid MKxGPIO Command at the DSP
        GpioInvalidCmdDsp                     = -10800,
        /// GPIO Internal Failure
        GpioInternalError                     = -10801,
        /// Received ARM Log command with invalid type
        InvalidArmlogType                     = -10900,
        /// Received DSP Log command with invalid type
        InvalidDsplogType                     = -10901,
        /// Internal ARM Log error due to an internal corruption
        ArmlogInternalError                   = -10902,
        /// C2XSec module received a message that is too short to even contain a USN
        C2xsecMsgTooShortNoUsn             = -11000,
        /// C2XSec module received a command that is too short in length
        C2xsecCmdTooShort                    = -11001,
        /// C2XSec module received a message containing an unsupported instruction
        C2xsecInsNotSupported                = -11002,
        /// C2XSec module received an invalid curve ID
        C2xsecCurveidInvalid                  = -11003,
        /// C2XSec module received a command whose length does not match its curve ID
        C2xsecSizeMismatchForCurveid        = -11004,
        /// C2XSec module received a reconstruct ECC public key command with wrong LC
        C2xsecRepkWrongLc                    = -11005,
        /// C2XSec module received a reconstruct ECC public key command with wrong
        /// length
        C2xsecRepkWrongLength                = -11006,
        /// C2XSec module received a decompress public key command with wrong LC
        C2xsecDpkWrongLc                     = -11007,
        /// C2XSec module received a decompress public key command with wrong length
        C2xsecDpkWrongLength                 = -11008,
        /// C2XSec module received a verify signature of hash command with wrong LC
        C2xsecVsohWrongLc                    = -11009,
        /// C2XSec module received a verify signature of hash command with wrong
        /// length
        C2xsecVsohWrongLength                = -11010,
        /// C2XSec module received a decompress public key and verify signature of
        /// hash command with wrong LC
        C2xsecDpkVsohWrongLc                = -11011,
        /// C2XSec module received a decompress public key and verify signature of
        /// hash command with wrong length
        C2xsecDpkVsohWrongLength            = -11012,
        /// ECDSA accelerator timeout during verify signature of hash operation
        /// for NIST256 curve ID
        C2xsecNist256VsohTimeout             = -11013,
        /// ECDSA accelerator timeout during decompress public key and verify
        /// signature of hash operation for NIST256 curve ID
        C2xsecNist256DpkVsohTimeout         = -11014,
        /// ECDSA accelerator timeout during decompress public key operation
        /// for NIST256 curve ID
        C2xsecNist256DpkTimeout              = -11015,
        /// ECDSA accelerator timeout during reconstruct ecc public key operation
        /// for NIST256 curve ID
        C2xsecNist256RepkTimeout             = -11016,
        /// ECDSA accelerator timeout during verify signature of hash operation
        /// for BP256R1 curve ID
        C2xsecBp256r1VsohTimeout             = -11017,
        /// ECDSA accelerator timeout during decompress public key and verify
        /// signature of hash operation for BP256R1 curve ID
        C2xsecBp256r1DpkVsohTimeout         = -11018,
        /// ECDSA accelerator timeout during decompress public key operation
        /// for BP256R1 curve ID
        C2xsecBp256r1DpkTimeout              = -11019,
        /// ECDSA accelerator timeout during reconstruct ecc public key operation
        /// for BP256R1 curve ID
        C2xsecBp256r1RepkTimeout             = -11020,
        /// ECDSA accelerator timeout during verify signature of hash operation
        /// for BP384R1 curve ID
        C2xsecBp384r1VsohTimeout             = -11021,
        /// ECDSA accelerator timeout during decompress public key and verify
        /// signature of hash operation for BP384R1 curve ID
        C2xsecBp384r1DpkVsohTimeout         = -11022,
        /// ECDSA accelerator timeout during decompress public key operation
        /// for BP384R1 curve ID
        C2xsecBp384r1DpkTimeout              = -11023,
        /// ECDSA accelerator timeout during reconstruct ecc public key operation
        /// for BP384R1 curve ID
        C2xsecBp384r1RepkTimeout             = -11024,
        /// ECDSA accelerator timeout during verify signature of hash (fail) self
        /// test operation for NIST256 curve ID
        C2xsecNist256SelftestVsohfTimeout   = -11025,
        /// ECDSA accelerator verify signature of hash (fail) self test result
        /// mismatch for NIST256 curve ID
        C2xsecNist256SelftestVsohfMismatch  = -11026,
        /// ECDSA accelerator timeout during verify signature of hash (pass) self
        /// test operation for NIST256 curve ID
        C2xsecNist256SelftestVsohpTimeout   = -11027,
        /// ECDSA accelerator verify signature of hash (pass) self test result
        /// mismatch for NIST256 curve ID
        C2xsecNist256SelftestVsohpMismatch  = -11028,
        /// ECDSA accelerator timeout during decompress public key self test operation
        /// for NIST256 curve ID
        C2xsecNist256SelftestDpkTimeout     = -11029,
        /// ECDSA accelerator decompress public key self test result mismatch
        /// for NIST256 curve ID
        C2xsecNist256SelftestDpkMismatch    = -11030,
        /// ECDSA accelerator timeout during reconstruct ecc public key operation
        /// for NIST256 curve ID
        C2xsecNist256SelftestRepkTimeout    = -11031,
        /// ECDSA accelerator reconstruct ECC public key self test result mismatch
        /// for NIST256 curve ID
        C2xsecNist256SelftestRepkMismatch   = -11032,
        /// C2XSec module detected internal memory corruption
        C2xsecMemoryCorruption1              = -11033,
        /// C2XSec module detected internal memory corruption
        C2xsecMemoryCorruption2              = -11034,
        /// C2XSec module detected internal memory corruption
        C2xsecMemoryCorruption3              = -11035,
        /// C2XSec module detected internal memory corruption
        C2xsecMemoryCorruption4              = -11036,
        /// Too many invalid 1PPS events
        Invalid1ppsEvent                      = -11100,
        /// Received invalid API Version length
        InvalidApiversionLength               = -11200,
        /// Received invalid Tx Packet length
        InvalidTxpacketLength                 = -11201,
        /// Radio config message length invalid
        InvalidRadioconfigLength              = -11202,
        /// Received invalid Flush Queue length
        InvalidFlushqLength                   = -11203,
        /// Invalid input parameter value for Cmd of tMKxSetTSF
        InvalidSetTsfLength                  = -11204,
        /// Received invalid GetTSF length
        InvalidGetTsfLength                  = -11205,
        /// Debug message length invalid
        InvalidDebugmsgLength                 = -11206,
        /// Received Calibration command with invalid length
        InvalidCalibrationLength              = -11207,
        /// Received Set Temperature command with invalid length
        InvalidTempLength                     = -11208,
        /// Received AuxADC Configuration command with invalid length
        InvalidAuxadccfgLength                = -11209,
        /// Received LOG command with invalid length
        InvalidLogLength                      = -11210,
        /// Received GPIO command with invalid length
        InvalidGpioLength                     = -11211,
        /// Received Reset command with invalid length
        InvalidResetLength                    = -11212,
        /// Received Fault command with invalid length
        InvalidFaultLength                    = -11213,
        /// SDIO interface detected an SDIO data transfer error
        SdioErrorCallback                     = -11300,
        /// Could not write to SDIO interface
        SdioWriteFailed                       = -11301,
        /// SDIO interface upload callback watchdog triggered
        SdioUploadTimeout                     = -11302,
        /// SDIO upload queue out of sync with upload request
        SdioQueueSyncFailure                 = -11303,
        /// Radio config received at DSP with invalid radio mode
        DspInvalidRadioMode                  = -11400,
        /// Received invalid SetTSF command at DSP
        DspSetTsfCmdInvalid                 = -11401,
        /// DSP Failed to boot
        DspInitWatchdog                       = -11402,
        /// DSP declared that ARM failed to initialise the Rx packet FIFO
        DspRxmacInitWatchdog                 = -11403,
        /// Ethernet configuration failed
        EthConfigFailed                       = -11500,
        /// Ethernet driver initialisation failed
        EthDrvInitFailed                     = -11501,
        /// Ethernet driver configuration failed
        EthDrvConfigFailed                   = -11502,
        /// Ethernet ARP initialisation failed
        EthArpInitFailed                     = -11503,
        /// Ethernet ARP Resolve failed
        EthArpResolveFailed                  = -11504,
        /// Ethernet socket failed to initialise
        EthSocketInitFailed                  = -11505,
        /// Ethernet failed to open the Tx socket to the host
        EthInvalidTxSocket                   = -11506,
        /// Ethernet failed to open the Rx socket to the host
        EthInvalidRxSocket                   = -11507,
        /// Ethernet initial UDP send failed
        EthInitialSendFailed                 = -11508,
        /// Ethernet UDP send failed
        EthUdpSendFailed                     = -11509,
        /// Ethernet Upload Callback Timeout
        EthUploadTimeout                      = -11510,
        /// Core Self Test range invalid
        CstRangeInvalid                       = -11600,
        /// Core Self Test failed
        CstTestFailed                         = -11601,
        /// DMA channel acquisiton for SPI driver failed
        SpiDmaAcqFailed                      = -11700,
        /// SPI driver configuration failed
        SpiConfigFailed                       = -11701,
        /// Initial SPI read/write failed
        SpiInitRwFailed                      = -11702,
        /// SPI Data available timeout.  Host not responded after 100ms
        SpiDavTimeout                         = -11703,
        /// SPI Hardware Error Callback
        SpiErrorCallback                      = -11704,
        /// TxWMAC DMA channel acquisition failed
        TxwmacDmaAcqFailed                   = -11800,
        /// TxWMAC acquired DMA channel configuration failed
        TxwmacDmaSetChanConfigFailed       = -11801,
        /// Setting TxWMAC DMA complete callback listener failed
        TxwmacDmaSetListenerFailed          = -11802,
        /// TxWMAC DMA channel enabling failed
        TxwmacDmaChanEnabledFailed          = -11803,
        /// TxWMAC DMA1 callback timeout (period = 100ms)
        TxwmacDma1Timeout                     = -11804,
        /// TxWMAC DMA2 callback timeout (period = 100ms)
        TxwmacDma2Timeout                     = -11805,
        /// TxWMAC DMA1 Invalid Callback Event
        TxwmacDma1InvalidEvent               = -11806,
        /// TxWMAC DMA2 Invalid Callback Event
        TxwmacDma2InvalidEvent               = -11807,
        /// DSP to ARM message send blocked (i.e. failed)
        DspMsgSendBlocked                    = -11900,
        /// ARM to DSP command send blocked
        DspCmdSendBlocked                    = -11901,
        /// TxMAC TxPacket parameters invalid
        TxmacTxpacketMalformed                = -12000,
        /// TxMAC TxPacket length parameter is too long
        TxmacTxpacketLengthTooLong          = -12001,
        /// TxMAC TxPacket Management frame length parameter is too long
        TxmacTxpacketMgmtLengthTooLong     = -12002,
        /// TxPHY TxPacket internal pointer invalid
        TxphyTxpacketPtrInvalid              = -12003,
        /// TxPHY TxPacket parameters invalid
        TxphyTxpacketMalformed                = -12004,
        /// Temperature I2C Ant 1 Sensor Failure
        TempI2cAnt1Failed                    = -12100,
        /// Temperature I2C Ant 2 Sensor Failure
        TempI2cAnt2Failed                    = -12101,
        /// Temperature Analog Ant 1 Sensor Failure
        TempAnalogAnt1Failed                 = -12102,
        /// Temperature Analog Ant 2 Sensor Failure
        TempAnalogAnt2Failed                 = -12103,
        /// Temperature Power Correction outside limits Ant1
        TempPowercalAnt1Invalid              = -12104,
        /// Temperature Power Correction outside limits Ant2
        TempPowercalAnt2Invalid              = -12105,
        /// TxPHY SF Encode failure
        TxSfencFailed                         = -12200,
        /// TxPHY Payload Encode failure
        TxPayloadencFailed                    = -12201,
        /// Tx Power Correction outside limits Ant1
        TxPowercalAnt1Invalid                = -12202,
        /// Tx Power Correction outside limits Ant2
        TxPowercalAnt2Invalid                = -12203,
        /// Tx Cyclic Shift Offset Out Of Bounds
        TxCyclicshiftInvalid                  = -12204,
        /// Rx Orbit RxSF failure
        RxRxsfFailed                          = -12300,
        /// Rx Orbit RxReDecode failure
        RxRxredecodeFailed                    = -12301,
        /// Rx AGC Unfreeze failure
        RxAgcunfreezeTimeout                  = -12302,
        /// Rx Coarse Timing failure
        RxCoarsetimingFailure                 = -12303,
        /// Rx Invalid Antenna during configuration
        RxStartInvalidAnt                    = -12304,
        /// Tx-Rx RF Loopback signal field decode failure (doesn't match expected)
        TxrxloopbackDecodeFailed              = -12400,
        /// Tx-RX RF Loopback Start_RxReDecode failure
        TxrxloopbackRxredecodeFailed          = -12401,
        /// Tx-RX RF Loopback RxSignalField failure
        TxrxloopbackRxsfFailed                = -12402,
        /// Tx-RX RF Loopback Coarse Timing failure
        TxrxloopbackCoarsetimeFailed          = -12403,
        /// Calibration of the TRX failure
        RfeTimeoutCaltrx                      = -12500,
        /// Calibration NewRadioConfig failure
        RfeTimeoutNewradioconfig              = -12501,
        /// ConfigManager Init failure
        RfeTimeoutConfiginit                  = -12502,
        /// Calibration GPIO update failure
        RfeTimeoutGpiopinupdate               = -12503,
        /// Register Write RFE falure
        RfeTimeoutRegisterwrite               = -12504,
        /// Overflow of the upload to the LLC of MKXIF_APIVERSION message
        LlcUploadOverflowApiversion          = -12600,
        /// Overflow of the upload to the LLC of MKXIF_TXPACKET message
        LlcUploadOverflowTxpacket            = -12601,
        /// Overflow of the upload to the LLC of MKXIF_GPIO buffer full message
        LlcUploadOverflowGpio                = -12602,
        /// Overflow of the upload to the LLC of MKXIF_LOOPBACK message
        LlcUploadOverflowLoopback            = -12603,
        /// Overflow of the upload to the LLC of MKXIF_FAULT message
        LlcUploadOverflowFault               = -12604,
        /// Overflow of the upload to the LLC of MKXIF_DEBUG Compensator message
        LlcUploadOverflowCompensator         = -12605,
        /// Overflow of the upload to the LLC of MKXIF_CALIBRATION message
        LlcUploadOverflowCalibration         = -12606,
        /// Compensator Processing Timeout
        CompensatorTimeout                     = -12700,
        /// Compensator CRC Failure
        CompensatorCrcFailure                 = -12701,
        /// TX Power Correction outside limits Ant1
        CompensatorPowercalAnt1Invalid       = -12702,
        /// TX Power Correction outside limits Ant2
        CompensatorPowercalAnt2Invalid       = -12703,
        /// No data is being received from the Compensator
        CompensatorNoDataReceived            = -12704,
        /// TimeSync Internal Failure
        TimesyncInternalFailure               = -12800,
        /// RxWMAC Received Corrupted Packet
        RxwmacCorruptPacket                   = -12900,
        /// ECC Double bit overflow error ARM IMEM
        FsmMemEccDoubleOverflowArmimem     = -13000,
        /// ECC Double bit error ARM IMEM
        FsmMemEccDoubleArmimem              = -13001,
        /// ECC Double bit overflow error ARM DMEM
        FsmMemEccDoubleOverflowArmdmem     = -13002,
        /// ECC Double bit error ARM DMEM
        FsmMemEccDoubleArmdmem              = -13003,
        /// ECC Double bit overflow error ECDSA
        FsmMemEccDoubleOverflowEcdsa       = -13004,
        /// ECC Double bit error error ECDSA
        FsmMemEccDoubleEcdsa                = -13005,
        /// Parity overflow error SYSMEM
        FsmMemParityOverflowSysmem          = -13006,
        /// Parity error SYSMEM
        FsmMemParitySysmem                   = -13007,
        /// Parity overflow error EMACTX
        FsmMemParityOverflowEmactx          = -13008,
        /// Parity error EMACTX
        FsmMemParityEmactx                   = -13009,
        /// Parity overflow error EMACRX
        FsmMemParityOverflowEmacrx          = -13010,
        /// Parity error EMACRX
        FsmMemParityEmacrx                   = -13011,
        /// Parity overflow error SDIOSRAM
        FsmMemParityOverflowSdiosram        = -13012,
        /// Parity error SDIOSRAM
        FsmMemParitySdiosram                 = -13013,
        /// Parity overflow error SDIOCISSRAM
        FsmMemParityOverflowSdiocissram     = -13014,
        /// Parity error SDIOCISSRAM
        FsmMemParitySdiocissram              = -13015,
        /// Parity overflow error ECDSA CRYPTO0
        FsmMemParityOverflowCrypto0         = -13016,
        /// Parity error ECDSA CRYPTO0
        FsmMemParityCrypto0                  = -13017,
        /// Parity overflow error ECDSA CRYPTO1
        FsmMemParityOverflowCrypto1         = -13018,
        /// Parity error ECDSA CRYPTO1
        FsmMemParityCrypto1                  = -13019,
        /// ECC Double bit overflow error BBEIRAM0
        FsmMemEccDoubleOverflowBbeiram0    = -13020,
        /// ECC Double bit error BBEIRAM0
        FsmMemEccDoubleBbeiram0             = -13021,
        /// ECC Double bit overflow error BBEIRAM1
        FsmMemEccDoubleOverflowBbeiram1    = -13022,
        /// ECC Double bit error BBEIRAM1
        FsmMemEccDoubleBbeiram1             = -13023,
        /// Parity overflow error BBEDRAM00
        FsmMemParityOverflowBbedram00       = -13024,
        /// Parity error BBEDRAM00
        FsmMemParityBbedram00                = -13025,
        /// Parity overflow error BBEDRAM01
        FsmMemParityOverflowBbedram01       = -13026,
        /// Parity error BBEDRAM01
        FsmMemParityBbedram01                = -13027,
        /// Parity overflow error BBEDRAM02
        FsmMemParityOverflowBbedram02       = -13028,
        /// Parity error BBEDRAM02
        FsmMemParityBbedram02                = -13029,
        /// Parity overflow error BBEDRAM03
        FsmMemParityOverflowBbedram03       = -13030,
        /// Parity error BBEDRAM03
        FsmMemParityBbedram03                = -13031,
        /// Parity overflow error BBEDRAM10
        FsmMemParityOverflowBbedram10       = -13032,
        /// Parity error BBEDRAM10
        FsmMemParityBbedram10                = -13033,
        /// Parity overflow error BBEDRAM11
        FsmMemParityOverflowBbedram11       = -13034,
        /// Parity error BBEDRAM11
        FsmMemParityBbedram11                = -13035,
        /// Parity overflow error ORBITSP0
        FsmMemParityOverflowOrbitsp0        = -13036,
        /// Parity error ORBITSP0
        FsmMemParityOrbitsp0                 = -13037,
        /// Parity overflow error ORBITSP1
        FsmMemParityOverflowOrbitsp1        = -13038,
        /// Parity error ORBITSP1
        FsmMemParityOrbitsp1                 = -13039,
        /// Parity overflow error ORBITSP2
        FsmMemParityOverflowOrbitsp2        = -13040,
        /// Parity error ORBITSP2
        FsmMemParityOrbitsp2                 = -13041,
        /// Parity overflow error ORBITSP3
        FsmMemParityOverflowOrbitsp3        = -13042,
        /// Parity error ORBITSP3
        FsmMemParityOrbitsp3                 = -13043,
        /// Parity overflow error ORBITDP0
        FsmMemParityOverflowOrbitdp0        = -13044,
        /// Parity error ORBITDP0
        FsmMemParityOrbitdp0                 = -13045,
        /// Parity overflow error ORBITDP1
        FsmMemParityOverflowOrbitdp1        = -13046,
        /// Parity error ORBITDP1
        FsmMemParityOrbitdp1                 = -13047,
        /// ECC Double bit overflow error X2
        FsmMemEccDoubleOverflowX2          = -13048,
        /// ECC Double bit error X2
        FsmMemEccDoubleX2                   = -13049,
        /// Parity overflow error X2DMEM0
        FsmMemParityOverflowX2dmem0         = -13050,
        /// Parity error X2DMEM0
        FsmMemParityX2dmem0                  = -13051,
        /// Parity overflow error X2DMEM1
        FsmMemParityOverflowX2dmem1         = -13052,
        /// Parity error X2DMEM1
        FsmMemParityX2dmem1                  = -13053,
        /// ECC single bit overflow error ARMIMEM
        FsmMemEccSingleOverflowArmimem     = -13070,
        /// ECC single bit error ARMIMEM
        FsmMemEccSingleArmimem              = -13071,
        /// ECC single bit overflow error ARMDMEM
        FsmMemEccSingleOverflowArmdmem     = -13072,
        /// ECC single bit error ARMDMEM
        FsmMemEccSingleArmdmem              = -13073,
        /// ECC single bit overflow error ECDSA
        FsmMemEccSingleOverflowEcdsa       = -13074,
        /// ECC single bit error ECDSA
        FsmMemEccSingleEcdsa                = -13075,
        /// ECC single bit overflow error BBEIRAM0
        FsmMemEccSingleOverflowBbeiram0    = -13076,
        /// ECC single bit error BBEIRAM0
        FsmMemEccSingleBbeiram0             = -13077,
        /// ECC single bit overflow error BBEIRAM1
        FsmMemEccSingleOverflowBbeiram1    = -13078,
        /// ECC single bit error BBEIRAM1
        FsmMemEccSingleBbeiram1             = -13079,
        /// ECC single bit overflow error X2
        FsmMemEccSingleOverflowX2          = -13080,
        /// ECC single bit error X2
        FsmMemEccSingleX2                   = -13081,
        /// BBE Write Response Error, Reserved address/Illegal write to BBE memory
        FsmMemDspIllegalWrite               = -13088,
        /// ARMWDT Interrupt Error
        FsmArmWatchdog                        = -13089,
        /// MDMWDT Interrupt Error
        FsmDspWatchdog                        = -13090,
        /// RFEWDT Interrupt Error
        FsmX2Watchdog                         = -13091,
        /// ARMPLL0 unlock Error (unused)
        FsmArmPll0Unlock                     = -13092,
        /// ARMPLL1 unlock Error (unused)
        FsmArmPll1Unlock                     = -13093,
        /// RFEPLL unlock Error (unused)
        FsmX2PllUnlock                       = -13094,
        /// Core self-test failure Exception Test Svc
        CstExceptionTestSvc                  = -14000,
        /// Core self-test failure Exception Test Pendsv
        CstExceptionTestPendsv               = -14001,
        /// Core self-test failure Exception Test Sys tick
        CstExceptionTestSystick              = -14002,
        /// Core self-test failure Exception Hard Fault1
        CstExceptionHardFault1               = -14003,
        /// Core self-test failure Exception Hard Fault2
        CstExceptionHardFault2               = -14004,
        /// Core self-test failure Exception Usage Fault
        CstExceptionUsageFault               = -14005,
        /// Core self-test failure Exception Mem Fault
        CstExceptionMemFault                 = -14006,
        /// Core self-test failure Exception Bus Fault
        CstExceptionBusFault                 = -14007,
        /// Core self-test failure Exception Test Nmihf
        CstExceptionTestNmihf                = -14008,
        /// Core self-test failure Exception Test Tail Chain
        CstExceptionTestTailchain            = -14009,
        /// Core self-test failure Exception Test Masking
        CstExceptionTestMasking              = -14010,
        /// Core self-test failure Exception Test Handler Thread
        CstExceptionTestHandler              = -14011,
        /// Core self-test failure Regbank Test4
        CstRegbankTest4                       = -14012,
        /// Core self-test failure ALU Test7
        CstAluTest7                           = -14013,
        /// Core self-test failure Branch Test3
        CstBranchTest3                        = -14014,
        /// Core self-test failure Status Test3
        CstStatusTest3                        = -14015,
        /// Core self-test failure Regbank Test6
        CstRegbankTest6                       = -14016,
        /// Core self-test failure Fetch Test
        CstFetchTest                          = -14017,
        /// Core self-test failure Load store Test6
        CstLoadstoreTest6                     = -14018,
        /// Core self-test failure Load store Test1
        CstLoadstoreTest1                     = -14019,
        /// Core self-test failure Load store Test2
        CstLoadstoreTest2                     = -14020,
        /// Core self-test failure Load store Test3
        CstLoadstoreTest3                     = -14021,
        /// Core self-test failure Load store Test4
        CstLoadstoreTest4                     = -14022,
        /// Core self-test failure Load store Test5
        CstLoadstoreTest5                     = -14023,
        /// Core self-test failure Regbank Test1
        CstRegbankTest1                       = -14024,
        /// Core self-test failure Regbank Test2
        CstRegbankTest2                       = -14025,
        /// Core self-test failure Regbank Test3
        CstRegbankTest3                       = -14026,
        /// Core self-test failure Regbank Test5
        CstRegbankTest5                       = -14027,
        /// Core self-test failure ALU Test1
        CstAluTest1                           = -14028,
        /// Core self-test failure ALU Test2
        CstAluTest2                           = -14029,
        /// Core self-test failure ALU Test3
        CstAluTest3                           = -14030,
        /// Core self-test failure ALU Test4
        CstAluTest4                           = -14031,
        /// Core self-test failure ALU Test5
        CstAluTest5                           = -14032,
        /// Core self-test failure ALU Test6
        CstAluTest6                           = -14033,
        /// Core self-test failure Branch Test1
        CstBranchTest1                        = -14034,
        /// Core self-test failure Status Test1
        CstStatusTest1                        = -14035,
        /// Core self-test failure MAC Test1
        CstMacTest1                           = -14036,
        /// Core self-test failure MAC Test2
        CstMacTest2                           = -14037,
        /// Core self-test failure Status Test2
        CstStatusTest2                        = -14038,
        /// Core self-test failure Branch Test2
        CstBranchTest2                        = -14039,
        /// Peripheral self-test outclk SAFEREF failure
        PstCguOutclk0Saferef                 = -14100,
        /// Peripheral self-test outclk ARM failure
        PstCguOutclk1Arm                     = -14101,
        /// Peripheral self-test outclk HSPI failure
        PstCguOutclk2Hspi                    = -14102,
        /// Peripheral self-test outclk AES failure
        PstCguOutclk3Aes                     = -14103,
        /// Peripheral self-test outclk BA414EP failure
        PstCguOutclk4Ba414ep                 = -14104,
        /// Peripheral self-test outclk SYSAPB failure
        PstCguOutclk5Sysapb                  = -14105,
        /// Peripheral self-test outclk WDT failure
        PstCguOutclk6Wdt                     = -14106,
        /// Peripheral self-test outclk PERIAPB failure
        PstCguOutclk7Periapb                 = -14107,
        /// Peripheral self-test outclk I2C failure
        PstCguOutclk8I2c                     = -14108,
        /// Peripheral self-test outclk UART failure
        PstCguOutclk9Uart                    = -14109,
        /// Peripheral self-test outclk QSPI failure
        PstCguOutclk10Qspi                   = -14110,
        /// Peripheral self-test outclk BBE16 failure
        PstCguOutclk11Bbe16                  = -14111,
        /// Peripheral self-test outclk TIMER failure
        PstCguOutclk12Timer                  = -14112,
        /// Peripheral self-test outclk RMII failure
        PstCguOutclk13Rmii                   = -14113,
        /// Peripheral self-test outclk RMIIRX failure
        PstCguOutclk14Rmiirx                 = -14114,
        /// Peripheral self-test outclk RMIITX failure
        PstCguOutclk15Rgmiitx                = -14115,
        /// Peripheral self-test outclk REF CLK1 failure
        PstCguOutclk16Refclk1                = -14116,
        /// Peripheral self-test outclk REF CLK2 failure
        PstCguOutclk17Refclk2                = -14117,
        /// Peripheral self-test outclk WRCK failure
        PstCguOutclk18Wrck                   = -14118,
        /// Peripheral self-test failure Bus interconnect AHB2APB SYS
        PstBusSys                             = -14119,
        /// Peripheral self-test failure Bus interconnect AHB2VPBT ARM Timers
        PstBusArmTimers                      = -14120,
        /// Peripheral self-test failure Bus interconnect AHB2VPBT RFE Timer
        PstBusRfeTimer                       = -14121,
        /// Peripheral self-test failure Bus interconnect ORBIT State CRC
        PstBusOrbitStateCrc                 = -14122,
        /// Peripheral self-test failure Chip Infra RGU
        PstChipInfraRgu                      = -14123,
        /// Peripheral self-test failure Chip Infra CREG
        PstChipInfraCreg                     = -14124,
        /// Peripheral self-test failure Chip Infra SCU Bank 2
        PstChipInfraScuBank2                = -14125,
        /// Peripheral self-test failure Chip Infra SCU Bank 3
        PstChipInfraScuBank3                = -14126,
        /// Peripheral self-test failure Chip Infra ARM Timers
        PstChipInfraArmTimers               = -14127,
        /// Peripheral self-test failure Chip Infra ARM Watchdog
        PstChipInfraArmWdt                  = -14128,
        /// Peripheral self-test failure Chip Infra DSP Watchdog
        PstChipInfraDspWdt                  = -14129,
        /// Peripheral self-test failure Peripheral Infra UART1
        PstPeriphInfraUart1                  = -14132,
        /// Peripheral self-test failure Peripheral Infra UART2
        PstPeriphInfraUart2                  = -14133,
        /// Peripheral self-test failure Peripheral Infra UART3
        PstPeriphInfraUart3                  = -14134,
        /// Peripheral self-test failure Peripheral Infra UART4
        PstPeriphInfraUart4                  = -14135,
        /// Peripheral self-test failure Peripheral Infra QSPI
        PstPeriphInfraQspi                   = -14136,
        /// Peripheral self-test failure Peripheral Infra I2C
        PstPeriphInfraI2c                    = -14137,
        /// Peripheral self-test failure Peripheral Infra I2C Internal Regs
        PstPeriphInfraI2cint                 = -14138,
        /// Peripheral self-test failure Peripheral Infra GPIO Toggle
        PstPeriphInfraGpioToggle            = -14139,
        /// Peripheral self-test failure Peripheral Infra GPIO Loopback
        PstPeriphInfraGpioLoopback          = -14140,
        /// Peripheral self-test failure DMA
        PstDma                                 = -14141,
        /// Peripheral self-test failure ECDSA
        PstEcdsa                               = -14142,
        /// Peripheral self-test failure Verify OTP
        PstVerifyOtp                          = -14143,
        /// Peripheral self-test failure OTP Integrity NXP bank
        PstOtpIntegrityNxp                   = -14144,
        /// Peripheral self-test failure OTP Integrity Customer bank
        PstOtpIntegrityCustomer              = -14145,
        /// PST clock test requested is out of range
        PstCguClocksOutofrange               = -14200,
        /// PST clocks test config is invalid (0/null)
        PstCguClocksInvalidconfig            = -14201,
        /// PST Orbit failure for MCS0
        PstOrbitFailureMcs0                  = -14300,
        /// PST Orbit failure for MCS1
        PstOrbitFailureMcs1                  = -14301,
        /// PST Orbit failure for MCS2
        PstOrbitFailureMcs2                  = -14302,
        /// PST Orbit failure for MCS3
        PstOrbitFailureMcs3                  = -14303,
        /// PST Orbit failure for MCS4
        PstOrbitFailureMcs4                  = -14304,
        /// PST Orbit failure for MCS5
        PstOrbitFailureMcs5                  = -14305,
        /// PST Orbit failure for MCS6
        PstOrbitFailureMcs6                  = -14306,
        /// PST Orbit failure for MCS7
        PstOrbitFailureMcs7                  = -14307,
        /// Memory self-test was completed but test failed for some mem ring(s)
        MbistCompletedFailed                  = -14400,
        /// Memory self-test was not completed (aborted), thus failed
        MbistNotCompletedFailed              = -14401,
        /// Boot status PBL to SBL booting failure
        BootStatusBootFailure                = -14500,
        /// Boot status PBL to SBL Read over i/f failure
        BootStatusReadFailure                = -14501,
        /// Boot status PBL to SBL phase Authentication failure
        BootStatusAuthFailure                = -14502,
        /// Boot status PBL to SBL phase ID verification failure
        BootStatusIdVerfFailure             = -14503,
        /// Boot status PBL to SBL phase BSH not found failure
        BootStatusBshNotFound               = -14504,
        /// Boot status PBL to SBL phase BSH ended unexpected failure
        BootStatusBshEndedFailure           = -14505,
        /// Boot status PBL to SBL phase invalid target address failure
        BootStatusInvalidTargetAddr         = -14506,
        /// Boot status PBL to SBL phase invalid boot command
        BootStatusInvalidCmd                 = -14507,
        /// Boot status PBL to SBL phase invalid boot mode
        BootStatusInvalidBootMode           = -14508,
        /// Boot status PBL to SBL phase flash invalid address
        BootStatusFlashInvalidAddr          = -14509,
        /// Boot status PBL to SBL phase decryption failure
        BootStatusDecryptionFailure          = -14510,
        /// Boot status PBL to SBL phase security init failure
        BootStatusSecurityInitFailure       = -14511,
        /// Boot status PBL to SBL phase security OTP read failure
        BootStatusSecurityOtpReadFailure   = -14512,
        /// Boot status PBL to SBL phase security config mismatch failure
        BootStatusSecurityConfigMismatch    = -14513,
        /// Boot status PBL to SBL phase CRC check failure
        BootStatusCrcCheckFailure           = -14514,
        /// Boot status PBL to SBL phase chunk id verification failure
        BootStatusChunkIdVerfFailure       = -14515,
        /// Boot status PBL to SBL phase image format mismatch failure
        BootStatusImgFormatMismatch         = -14516,
        /// Boot status PBL to SBL phase public key verification failure
        BootStatusPubKeyVerfFailure        = -14517,
        /// Boot status PBL to SBL phase customer OTP not programmed failure
        BootStatusCustomerOtpNotProg       = -14518,
        /// Boot status PBL to SBL phase Flash init failure
        BootStatusFlashInitFailure          = -14519,
        /// Invalid input parameter value for RadioID of tMKxTxPacket
        InvalidinputTxpktRadioid              = -15000,
        /// Invalid input parameter value for ChannelID of tMKxTxPacket
        InvalidinputTxpktChannelid            = -15001,
        /// Invalid input parameter value for TxAntenna of tMKxTxPacket
        InvalidinputTxpktTxant                = -15002,
        /// Invalid input parameter value for MCS of tMKxTxPacket
        InvalidinputTxpktMcs                  = -15003,
        /// Invalid input parameter value for TxPower of tMKxTxPacket
        InvalidinputTxpktTxpower              = -15004,
        /// Invalid input parameter value for TxFrameLength of tMKxTxPacket
        InvalidinputTxpktTxframelength        = -15005,
        /// Invalid input parameter value for Cmd of tMKxSetTSF
        InvalidinputSettsfCmd                 = -15100,
        /// Invalid input parameter value for UTC of tMKxSetTSF
        InvalidinputSettsfUtc                 = -15101,
        /// Invalid input parameter value for TSF of tMKxSetTSF
        InvalidinputSettsfTsf                 = -15102,
        /// Invalid input parameter value for Mode of tMKxRadioConfig
        InvalidinputRadiocfgMode              = -15200,
        /// Invalid input parameter value for ChannelFreq of tMKxRadioConfig
        InvalidinputRadiocfgChannelfreq       = -15201,
        /// Invalid input parameter value for Bandwidth of tMKxRadioConfig
        InvalidinputRadiocfgBw                = -15202,
        /// Invalid input parameter value for TxAntenna of tMKxRadioConfig
        InvalidinputRadiocfgTxant             = -15203,
        /// Invalid input parameter value for RxAntenna of tMKxRadioConfig
        InvalidinputRadiocfgRxant             = -15204,
        /// Invalid input parameter value for DefaultMCS of tMKxRadioConfig
        InvalidinputRadiocfgDefaultmcs        = -15205,
        /// Invalid input parameter value for DefaultTxPower of tMKxRadioConfig
        InvalidinputRadiocfgDefaulttxpower    = -15206,
        /// Invalid input parameter value for DualTxControl of tMKxRadioConfig
        InvalidinputRadiocfgDualtxctrl        = -15207,
        /// Invalid input parameter value for CSThreshold of tMKxRadioConfig
        InvalidinputRadiocfgCsthresh          = -15208,
        /// Invalid input parameter value for CBRThreshold of tMKxRadioConfig
        InvalidinputRadiocfgCbrthresh         = -15209,
        /// Invalid input parameter value for SlotTime of tMKxRadioConfig
        InvalidinputRadiocfgSlottime          = -15210,
        /// Invalid input parameter value for DIFSTime of tMKxRadioConfig
        InvalidinputRadiocfgDifstime          = -15211,
        /// Invalid input parameter value for SIFSTime of tMKxRadioConfig
        InvalidinputRadiocfgSifstime          = -15212,
        /// Invalid input parameter value for EFISTime of tMKxRadioConfig
        InvalidinputRadiocfgEifstime          = -15213,
        /// Invalid input parameter value for ShortRetryLimit of tMKxRadioConfig
        InvalidinputRadiocfgShortretry        = -15214,
        /// Invalid input parameter value for LongRetryLimit of tMKxRadioConfig
        InvalidinputRadiocfgLongretry         = -15215,
        /// Invalid input parameter value for TxQueue.AIFS of tMKxRadioConfig
        InvalidinputRadiocfgAifs              = -15216,
        /// Invalid input parameter value for TxQueue.CWMIN of tMKxRadioConfig
        InvalidinputRadiocfgCwmin             = -15217,
        /// Invalid input parameter value for TxQueue.CWMAX of tMKxRadioConfig
        InvalidinputRadiocfgCwmax             = -15218,
        /// Invalid input parameter value for TxQueue.TXOP of tMKxRadioConfig
        InvalidinputRadiocfgTxop              = -15219,
        /// Invalid input parameter value for IntervalDuration of tMKxRadioConfig
        InvalidinputRadiocfgInterval          = -15220,
        /// Invalid input parameter value for GuardDuration of tMKxRadioConfig
        InvalidinputRadiocfgGuard             = -15221,
        /// Invalid input parameter value for RadioID of tMKxFlushQueue
        InvalidinputFlushqRadioid             = -15300,
        /// Invalid input parameter value for ChannelID of tMKxFlushQueue
        InvalidinputFlushqChannelid           = -15301,
        /// Invalid input parameter value for TxQueue of tMKxFlushQueue
        InvalidinputFlushqTxqueue             = -15302,
        /// Invalid input parameter value for Version of tMKxCalibration
        InvalidinputCalibVersion              = -15400,
        /// Invalid input parameter value for CompensatorSel of tMKxCalibration
        InvalidinputCalibCompensatorsel       = -15401,
        /// INVALID INPUT parameter value for TxPowerCalMode of tMKxCalibration
        InvalidinputCalibTxpowercalmode       = -15402,
        /// Invalid input parameter value for RSSICalMode of tMKxCalibration
        InvalidinputCalibRssicalmode          = -15403,
        /// Invalid input parameter value for CompensatorReturn of tMKxCalibration
        InvalidinputCalibCompreturn           = -15404,
        /// Invalid input parameter value Compensator.TxPowerThresh of tMKxCalibration
        InvalidinputCalibComppowerthresh      = -15405,
        /// Invalid input parameter value for Compensator.Alpha of tMKxCalibration
        InvalidinputCalibCompalpha            = -15406,
        /// Invalid input parameter value for Compensator.Beta of tMKxCalibration
        InvalidinputCalibCompbeta             = -15407,
        /// Invalid input parameters value PALNA.Alpha + PALNA.Beta != 256
        InvalidinputCalibCompalphabeta        = -15408,
        /// Invalid input parameter value for PALNA.TxPowerThresh of tMKxCalibration
        InvalidinputCalibPalnapowerthresh     = -15409,
        /// Invalid input parameter value for PALNA.Alpha of tMKxCalibration
        InvalidinputCalibPalnaalpha           = -15410,
        /// Invalid input parameter value for PALNA.Beta of tMKxCalibration
        InvalidinputCalibPalnabeta            = -15411,
        /// Invalid input parameters value PALNA.Alpha + PALNA.Beta != 256
        InvalidinputCalibPalnaalphabeta       = -15412,
        /// Invalid input parameter value for TxPowerExtraDrive of tMKxCalibration
        InvalidinputCalibExtradrive           = -15413,
        /// Invalid input parameter value for TxPowerLimitMaxPower of tMKxCalibration
        InvalidinputCalibLimitmaxpower        = -15414,
        /// Invalid input parameter value for Temp SensorSource of tMKxCalibration
        InvalidinputCalibTempsensor           = -15415,
        /// Invalid input parameter value for I2CAddrSensor1 of tMKxCalibration
        InvalidinputCalibTempi2caddrsensor1   = -15416,
        /// Invalid input parameter value for I2CAddrSensor2 of tMKxCalibration
        InvalidinputCalibTempi2caddrsensor2   = -15417,
        /// Invalid input parameter value for PAEnableGPIO of tMKxCalibration
        InvalidinputCalibPaenablegpio         = -15418,
        /// Invalid input parameter value for LNAEnableGPIO of tMKxCalibration
        InvalidinputCalibLnaenablegpio        = -15419,
        /// Invalid input parameter value for RemotePAEnableGPIO of tMKxCalibration
        InvalidinputCalibRemotepagpio         = -15420,
        /// Invalid input parameter value for C1GPIO of tMKxCalibration
        InvalidinputCalibC1gpio               = -15421,
        /// Invalid input parameter value for TxClaimGPIO of tMKxCalibration
        InvalidinputCalibTxclaimgpio          = -15422,
        /// Invalid input parameter value for CompensatorEnableGPIO of tMKxCalibration
        InvalidinputCalibCompengpio           = -15423,
        /// Invalid input parameter value for Timing.PAEnableLNADisable
        InvalidinputCalibTimingpaen           = -15424,
        /// Invalid input parameter value for Timing.BasebandStart of tMKxCalibration
        InvalidinputCalibTimingbbstart        = -15425,
        /// Invalid input parameter value for Timing.AuxillaryADC of tMKxCalibration
        InvalidinputCalibTimingauxadc         = -15426,
        /// Invalid input parameter value for Timing.RemotePADisable
        InvalidinputCalibTimingremotepa       = -15427,
        /// Invalid input parameter value for Timing.PADisable of tMKxCalibration
        InvalidinputCalibTimingpadis          = -15428,
        /// Invalid input parameter value for Timing.LNAEnable of tMKxCalibration
        InvalidinputCalibTiminglnaen          = -15429,
        /// Invalid input parameter value for OnePPSGPIO of tMKxCalibration
        InvalidinputCalib1ppsgpio             = -15430,
        /// Invalid input parameter value for CCAGPIO of tMKxCalibration
        InvalidinputCalibCcagpio              = -15431,
        /// Invalid input parameter value for TxActiveGPIO of tMKxCalibration
        InvalidinputCalibTxactivegpio         = -15432,
        /// Invalid input parameter value for RxActiveGPIO of tMKxCalibration
        InvalidinputCalibRxactivegpio         = -15433,
        /// Invalid input parameter value for OtherRadioTxActiveGPIO
        InvalidinputCalibOthertxgpio          = -15434,
        /// Invalid input parameter value for OtherRadioRxActiveGPIO
        InvalidinputCalibOtherrxgpio          = -15435,
        /// Invalid input parameter value for Ant1 ATemp.AuxADCInput (tMKxCalibration)
        InvalidinputCalibAtempant1auxadc      = -15436,
        /// Invalid input parameter value for Ant2 ATemp.AuxADCInput (tMKxCalibration)
        InvalidinputCalibAtempant2auxadc      = -15437,
        /// Invalid input parameter value for Temp.TempPAAnt1 of tMKxTemp
        InvalidinputTempPaant1                = -15500,
        /// Invalid input parameter value for Temp.TempPAAnt2 of tMKxTemp
        InvalidinputTempPaant2                = -15501,
        /// Invalid input parameter value for GPIO.Cmd of tMKxGPIO
        InvalidinputGpioCmd                   = -15600,
        /// Invalid input parameter value for GPIO.PinNumber of tMKxGPIO
        InvalidinputGpioPin                   = -15601,
        /// Invalid input parameter value for GPIO.Value of tMKxGPIO
        InvalidinputGpioValue                 = -15602,
        /// Invalid input parameter value for Cmd of tMKxFault
        InvalidinputFaultCmd                  = -15700,
        /// Invalid input parameter value for CommandErrorCode of tMKxFault
        InvalidinputFaultCmderrorcode         = -15701,
        /// USB interface device not present
        UsbDeviceNotPresent                  = -16100,
        /// The LLC kernel module encountered an invalid configuration of the SPI
        /// hardware while initialising the SPI interface
        SpiDeviceNotPresent                  = -16200,
        /// An operation by the LLC kernel module on the SPI interface timed out
        /// (1 second)
        SpiInterfaceTimeout                   = -16201,
        /// The allocation by the LLC kernel module of a buffer to upload into,
        /// from the device failed
        SpiBufferAllocationFailure           = -16202,
        /// The queue used by the LLC kernel module for input transfers using the
        /// SPI interface was exhausted
        SpiInputQueueExhausted               = -16203,
        /// An error was encountered by the LLC kernel module when examining the
        /// contents of the output transfer queue used for SPI interface transfers
        SpiOutputQueueError                  = -16204,
        /// An invalid transfer structure was encountered by the LLC kernel module
        /// when trying to perform a transfer on the SPI interface
        SpiInvalidTransferStructure          = -16205,
        /// An invalid output transfer structure was encountered by the the LLC
        /// kernel module when trying to perform a transfer on the SI interface
        SpiInvalidOutputContext              = -16206,
        /// The ring buffer used by the LLC kernel module for output transfers
        /// on the SPI interface was overrun
        SpiBufferOverrun                      = -16207,
        /// The LLC kernel module encountered a system error when requesting a
        /// transfer on the SPI interface
        SpiSystemError                        = -16208,
        /// A critical structure used by the LLC kernel module when performing a
        /// transfer on the SPI interface was invalid
        SpiInvalidCriticalStructures         = -16209,
        /// The LLC kernel module encountered an invalid device ID when handling
        /// an interrupt from the SPI interface
        SpiInvalidDeviceId                   = -16210,
        /// The corrupted structure associated with a transfer on the SPI interface
        /// was encountered by the LLC kernel module
        SpiMemoryCorruption                   = -16211,
        /// A memory allocation failure was encountered by the LLC kernel module
        /// when using the SPI interface
        SpiMemoryAllocationFailure           = -16212,
        /// The LLC kernel module encountered invalid SPI hardware configuration
        /// information when attempting to initialise the SPI interface
        SpiInitErrorDeviceNotPresent       = -16213,
        /// The LLC kernel module encountered already initialised SPI hardware
        /// when attempting to initialise the SPI interface
        SpiInitErrorDeviceAlreadySetup     = -16214,
        /// The LLC kernel module was unable to allocate Tx cache memory
        /// when attempting to initialise the SPI interface
        SpiSystemCacheAllocFailure          = -16215,
        /// The LLC kernel module encountered an initialisation failure of a
        /// list structure used with the SPI interface
        SpiSystemListInitError              = -16216,
        /// The LLC kernel module encountered an allocation failure of a
        /// list structure used with the SPI interface
        SpiSystemListItemAllocError        = -16217,
        /// The LLC kernel module encountered a failure of an operation on a
        /// list structure used with the SPI interface
        SpiSystemListItemAddError          = -16218,
        /// The LLC kernel module encountered a system error when requesting a
        /// pointer to the SPI interface bus master structure
        SpiSystemBusToMasterError          = -16219,
        /// The LLC kernel module SPI interface configuration was observed to be
        /// inconsistent with the system
        SpiSystemInvalidChipselect           = -16220,
        /// The LLC kernel module encountered a system error when requesting the
        /// SPI device to be used be added to the SPI bus during initialisation
        SpiSystemAddDeviceError             = -16221,
        /// The LLC kernel module encountered a system error when requesting
        /// access to the DAV pin used for interrupt based SPI operation
        SpiSystemDavPinRequestError        = -16222,
        /// The LLC kernel module encountered a system error when requesting
        /// the system associate the DAV pin with an IRQ handling function
        SpiSystemDavToIrqRequestError     = -16223,
        /// The LLC kernel module encountered an invalid SPI operating mode when
        /// initialising the SPI interface
        SpiInvalidSpiMode                    = -16224,
        /// The LLC kernel module encountered an SPI interrupt while the module
        /// was not in an enabled state
        SpiInterruptButNotEnabled           = -16225,
        /// The LLC kernel module attempted to initialise the SDIO interface
        /// without it being required
        SdioDeviceNotRequired                = -16300,
        /// An operation by the LLC kernel module on the SDIO interface timed out
        /// (1 second)
        SdioInterfaceTimeout                  = -16301,
        /// The LLC kernel module encountered a failure when attempting to
        /// enable the SDIO interface interrupt essential for receving data
        SdioEnableInterruptFailure           = -16303,
        /// The LLC kernel module encountered a failure when attempting to
        /// disable the SDIO interface interrupt used for receving data
        SdioDisableInterruptFailure          = -16304,
        /// The LLC kernel module encountered a failure when attempting to clear
        /// the SDIO interface interrupt
        SdioClearInterruptFailure            = -16305,
        /// The LLC kernel module encountered a failure when attempting to write
        /// to the SDIO device
        SdioSystemWriteToDeviceFailure     = -16306,
        /// The LLC kernel module encountered a failure when attempting to read
        /// data from the SDIO device
        SdioSystemReadFromDeviceFailure    = -16308,
        /// The LLC kernel module was unable to register the SDIO unable to
        /// register the driver with the system
        SdioSystemRegisterDriverFailure     = -16309,
        /// The LLC kernel module encountered an initialisation failure of a
        /// list structure used with the SDIO interface
        SdioSystemListInitError             = -16310,
        /// The LLC kernel module encountered an allocation failure of a
        /// list structure used with the SDIO interface
        SdioSystemListItemAllocError       = -16311,
        /// The LLC kernel module encountered a failure of an operation on a
        /// list structure used with the SDIO interface
        SdioSystemListItemAddError         = -16312,
        /// The LLC kernel module encountered a failure when attempting to
        /// enable the SDIO interface through the system
        SdioSystemFunctionEnableError       = -16313,
        /// The LLC kernel module encountered a failure when attempting to
        /// set the SDIO interface data transfer block size
        SdioSystemSetBlockSizeError        = -16314,
        /// The LLC kernel module encountered a failure when attempting to
        /// read a byte from the SDIO device
        SdioSystemReadByteError             = -16315,
        /// The LLC kernel module encountered a failure when attempting to
        /// write a byte to the SDIO device
        SdioSystemWriteByteError            = -16316,
        /// The corrupted structure associated with a transfer on the SDIO interface
        /// was encountered by the LLC kernel module
        SdioMemoryCorruption                  = -16317,
        /// The LLC kernel module was asked to send data out on the SDIO interface
        /// with the module not being in an enabled state
        SdioOutNotEnabled                    = -16318,
        /// The LLC kernel module was asked to receive data on the SDIO interface
        /// with the module not being in an enabled state
        SdioInNotEnabled                     = -16319,
        /// The LLC kernel module attempted to use the SDIO interface but
        /// system pointer to the device structure was NULL
        SdioSystemFunctionNotEnabled        = -16320,
        /// The queue used by the LLC kernel module for input transfers using the
        /// SDIO interface was exhausted
        SdioInputQueueExhausted              = -16321,
        /// The LLC kernel module encountered a request to read zero bytes from
        /// the device over the SDIO interface
        SdioZeroUploadLength                 = -16322,
        /// The LLC kernel module encountered a corrupted message that was read
        /// from the device over the SDIO interface
        SdioCorruptedInputPacket             = -16323,
        /// A memory allocation failure was encountered by the LLC kernel module
        /// when using the SDIO interface
        SdioMemoryAllocationFailure          = -16324,
        /// The LLC kernel module encountered an invalid configuration of the
        /// Eth hardware while initialising the ETH interface
        EthDeviceNotPresent                  = -16400,
        /// The corrupted structure associated with a transfer on the Eth interface
        /// was encountered by the LLC kernel module
        EthMemoryCorruption                   = -16401,
        /// The LLC kernel module encountered a corrupted message that was read
        /// from the device over the Eth interface
        EthCorruptedInputPacket              = -16402,
        /// The LLC kernel module encountered a missing socket when attempting to
        /// use the Eth interface
        EthSocketMissing                      = -16403,
        /// The queue used by the LLC kernel module for input transfers using the
        /// Eth interface was exhausted
        EthInputQueueExhausted               = -16404,
        /// A memory allocation failure was encountered by the LLC kernel module
        /// when using the Eth interface
        EthMemoryAllocationFailure           = -16405,
        /// The LLC kernel module encountered an error when attempting to transmit
        /// data via the Eth interface
        EthSystemTxError                     = -16406,
        /// The LLC kernel module encountered an error when attempting to receive
        /// data via the Eth interface
        EthSystemRxError                     = -16407,
        /// The LLC kernel module encountered an error when attempting to create
        /// a socket during the initialsation of the the Eth interface
        EthSystemRxSocketError              = -16408,
        /// The LLC kernel module encountered an error when attempting to bind to
        /// a socket during the initialsation of the the Eth interface
        EthSystemBindError                   = -16409,
        /// The LLC kernel module encountered an error when attempting to set the
        /// scheduling of the socket receive thread during the initialsation of
        /// the the Eth interface
        EthSystemSetSchedulerError          = -16410,
        /// The LLC kernel module encountered an initialisation failure of a
        /// list structure used with the Eth interface
        EthSystemListInitError              = -16411,
        /// The LLC kernel module encountered an allocation failure of a
        /// list structure used with the Eth interface
        EthSystemListItemAllocError        = -16412,
        /// The LLC kernel module encountered a failure of an operation on a
        /// list structure used with the Eth interface
        EthSystemListItemAddError          = -16413,
        /// The LLC kernel module encountered an overflow error when transmitting
        /// data via the Eth interface
        EthSystemOverflowError               = -16414,
        /// An operation by the LLC kernel module on the Eth interface timed out
        /// (1 second)
        EthInterfaceTimeout                   = -16415,
        /// The LLC kernel module was asked to send data out on the Eth interface
        /// with the module not being in an enabled state
        EthOutNotEnabled                     = -16416,
    }
}

enum_with_unknown! {
    /// NXP LLC radio identifier.
    pub enum Radio(u8) {
        /// Selection of the Radio A.
        RadioA = 0,
        /// Selection of the Radio B.
        RadioB = 1,
    }
}

impl Default for Radio {
    fn default() -> Self {
        Radio::RadioA
    }
}

enum_with_unknown! {
    /// NXP LLC radio channel config.
    pub enum Channel(u8) {
        /// Indicates Channel Config 0 is selected.
        Channel0 = 0,
        /// Indicates Channel Config 1 is selected.
        Channel1 = 1,
    }
}

impl Default for Channel {
    fn default() -> Self {
        Channel::Channel0
    }
}

enum_with_unknown! {
    /// NXP LLC Antenna Selection.
    pub enum Antenna(u8) {
        /// Invalid antenna
        Invalid   = 0,
        /// Transmit packet on antenna 1
        One       = 1,
        /// Transmit packet on antenna 2 (when available).
        Two       = 2,
        /// Transmit packet on both antenna
        OneAndTwo = 3,
        /// Selects the default (ChanConfig) transmit antenna setting
        Default   = 4,
    }
}

impl Default for Antenna {
    fn default() -> Self {
        Antenna::Default
    }
}

enum_with_unknown! {
    /// NXP LLC Modulation and Coding scheme.
    pub enum MCS(u8) {
        /// Rate 1/2 BPSK
        Rate12BPSK = 0xB,
        /// Rate 3/4 BPSK
        Rate34BPSK = 0xF,
        /// Rate 1/2 QPSK
        Rate12QPSK = 0xA,
        /// Rate 3/4 QPSK
        Rate34QPSK = 0xE,
        /// Rate 1/2 16QAM
        Rate12QAM16 = 0x9,
        /// Rate 3/4 16QAM
        Rate34QAM16 = 0xD,
        /// Rate 2/3 64QAM
        Rate23QAM64 = 0x8,
        /// Rate 3/4 64QAM
        Rate34QAM64 = 0xC,
        /// Use default data rate
        Default = 0x0,
        /// Use transmit rate control (currently unused)
        TRC = 0x1
    }
}

impl Default for MCS {
    fn default() -> Self {
        MCS::Default
    }
}

enum_with_unknown! {
    /// NXP LLC MAC layer tx control.
    /// These bits signal to the radio that special Tx behaviour is required.
    pub enum TxControl(u8) {
        /// Do not require any special behaviour
        RegularTransmission                  = 0x00,
        /// Do not modify the sequence number field
        DisableMacHeaderUpdatesSeqctrl       = 0x01,
        /// Do not modify the duration ID field
        DisableMacHeaderUpdatesDurationid    = 0x02,
        /// Do not modify the Ack Policy field
        DisableMacHeaderUpdatesAckpolicy     = 0x04,
        /// Do not modify the Retry field and set Max retries to zero
        DisableMacHeaderUpdatesRetry         = 0x08,
        /// Force the use of RTS/CTS with this packet
        ForceRtscts                          = 0x10
    }
}

impl Default for TxControl {
    fn default() -> Self {
        TxControl::RegularTransmission
    }
}

/// NXP LLC Tx power of frame, in 0.5dBm units.
#[repr(i16)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TxPower {
    /// Selects the PHY minimum transmit power.
    Min = -32768,
    /// Selects the PHY maximum transmit power.
    Max = 32767,
    /// Selects the PHY default transmit power level.
    Default = -32767,
    /// Custom transmit power level.
    Custom(i16),
}

impl Default for TxPower {
    fn default() -> Self {
        TxPower::Default
    }
}

impl From<i16> for TxPower {
    fn from(value: i16) -> Self {
        match value {
            -32768 => TxPower::Min,
            -32767 => TxPower::Default,
            32767 => TxPower::Max,
            _ => TxPower::Custom(value),
        }
    }
}

impl From<TxPower> for i16 {
    fn from(value: TxPower) -> Self {
        match value {
            TxPower::Custom(c) => c,
            TxPower::Min => -32768,
            TxPower::Default => -32767,
            TxPower::Max => 32767,
        }
    }
}

/// NXP LLC Rx power of frame, in 0.5dBm units.
#[repr(i16)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RxPower {
    /// Indicates when the Rx power reported is invalid as antenna is disabled.
    Disabled = -32768,
    /// Measured Rx power.
    Measured(i16),
}

impl From<i16> for RxPower {
    fn from(value: i16) -> Self {
        match value {
            -32768 => RxPower::Disabled,
            _ => RxPower::Measured(value),
        }
    }
}

impl From<RxPower> for i16 {
    fn from(value: RxPower) -> Self {
        match value {
            RxPower::Measured(m) => m,
            RxPower::Disabled => -32768,
        }
    }
}

enum_with_unknown! {
    pub enum RadioMode(u16) {
        /// Radio is off.
        Off = 0,
        /// Radio is using channel config 0 configuration only.
        Channel0 = 1,
        /// Radio is enabled to use channel config 1 configuration only.
        Channel1 = 2,
        /// Radio is enabled to channel switch between config 0 & config 1 configs.
        Switching = 3,
        /// Radio configuration read request.
        ReadCfg = 0x8080,
    }
}

enum_with_unknown! {
    pub enum Bandwidth(u8) {
        /// Bandwidth is 10MHz.
        TenMHz = 10,
        /// Bandwidth is 20MHz.
        TwentyMHz = 20,
    }
}

enum_with_unknown! {
     /// Dual radio transmit control.
     /// Values to controls transmit behaviour according to activity on the
     /// other radio (inactive in single radio configurations).
    pub enum DualTxControl(u8) {
        /// Do not constrain transmissions.
        NONE = 0x00,
        /// Prevent transmissions when other radio is transmitting.
        TX = 0x01,
        /// Prevent transmissions when other radio is receiving.
        RX = 0x02,
        /// Prevent transmissions when other radio is transmitting or receiving.
        TXRX = 0x03,
    }
}

/// A read/write wrapper around an NXP LLC Header.
#[derive(Debug, PartialEq)]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    use crate::wire::field::*;

    // Interface message. These fields are always present.
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

    // Tx Packet Data message offsets.
    /// Indicate the radio that should be used (Radio A or Radio B).
    pub const TX_RADIO: usize = 12;
    /// Indicate the channel config for the selected radio.
    pub const TX_CHAN: usize = 13;
    /// Indicate the antennas upon which packet should be transmitted.
    pub const TX_ANT: usize = 14;
    /// Indicate the MCS to be used (may specify default).
    pub const TX_MCS: usize = 15;
    /// Indicate the power to be used (may specify default).
    pub const TX_PWR: Field = 16..18;
    /// Additional control over the transmitter behaviour.
    pub const TX_CTRL: usize = 18;
    /// Reserved.
    pub const TX_RESERVED_1: usize = 19;
    /// Indicate the expiry time as an absolute MAC time in microseconds.
    pub const TX_EXPIRY: Field = 20..28;
    /// Length of the frame (802.11 Header + Body, not including FCS).
    pub const TX_LEN: Field = 20..22;
    /// Reserved.
    pub const TX_RESERVED_2: Field = 22..24;
    /// Frame (802.11 Header + Body, not including FCS).
    pub const TX_PAYLOAD: Rest = 24..;

    // Rx Packet Data message offsets.
    /// Indicate the radio where the packet was received (Radio A or Radio B).
    pub const RX_RADIO: usize = 12;
    /// Indicate the channel config for the selected radio.
    pub const RX_CHAN: usize = 13;
    /// Indicate the data rate that was used.
    pub const RX_MCS: usize = 14;
    /// Indicates FCS passed for received frame.
    pub const RX_FCS_PASS: usize = 15;
    /// Indicate the received power on Antenna 1.
    pub const RX_PWR_ANT1: Field = 16..18;
    /// Indicate the received power on Antenna 2.
    pub const RX_PWR_ANT2: Field = 18..20;
    /// Indicate the receiver noise on Antenna 1.
    pub const RX_NOI_ANT1: Field = 20..22;
    /// Indicate the receiver noise on Antenna 2.
    pub const RX_NOI_ANT2: Field = 22..24;
    /// Estimated frequency offset of rx frame in Hz (with respect to local freq).
    pub const RX_FREQ_OFFSET: Field = 24..28;
    /// MAC Rx Timestamp, local MAC TSF time at which packet was received.
    pub const RX_TST: Field = 28..36;
    /// Length of the Frame (802.11 Header + Body, including FCS).
    pub const RX_FRAME_LEN: Field = 36..38;
    /// Channel centre frequency on which this packet was received.
    pub const RX_CHAN_FREQ: Field = 38..40;
    /// Reserved for future use
    pub const RX_RESERVED: Field = 40..56;
    /// Frame (802.11 Header + Body, including FCS)
    pub const RX_PAYLOAD: Rest = 56..;

    // Radio config message offsets
    /// Operation mode of the radio.
    pub const CFG_RADIO_MODE: Field = 12..14;
    /// System clock tick rate in MHz, a read-only field.
    /// Only when reading config from the radio chip.
    pub const CFG_CLOCK_FREQ: Field = 14..16;
    /// Channel 0 configuration.
    pub const CFG_CHAN_0: Field = 16..220;
    /// Channel 1 configuration.
    pub const CFG_CHAN_1: Field = 220..424;
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
        let data = LittleEndian::read_u16(&data[field::TYPE]);
        Message::from(data)
    }

    /// Return the message length field.
    #[inline]
    pub fn msg_len(&self) -> usize {
        let data = self.buffer.as_ref();
        LittleEndian::read_u16(&data[field::LEN]).into()
    }

    /// Return the sequence number field.
    #[inline]
    pub fn seq_num(&self) -> u16 {
        let data = self.buffer.as_ref();
        LittleEndian::read_u16(&data[field::SEQ_NUM])
    }

    /// Return the reference number field.
    #[inline]
    pub fn ref_num(&self) -> u16 {
        let data = self.buffer.as_ref();
        LittleEndian::read_u16(&data[field::REF_NUM])
    }

    /// Return the return value field.
    #[inline]
    pub fn ret(&self) -> Status {
        let data = self.buffer.as_ref();
        let data = LittleEndian::read_i16(&data[field::RET]);
        Status::from(data)
    }

    /// Return the header length. The result depends on the value of
    /// the message type field.
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::TxPacket => field::TX_PAYLOAD.start,
            Message::RxPacket => field::RX_PAYLOAD.start,
            _ => field::RET.end,
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Header<&T> {
    /// Return a pointer to the payload.
    /// Depends of the packet type.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        match self.msg_type() {
            Message::RxPacket => &data[field::RX_PAYLOAD],
            Message::TxPacket => &data[field::TX_PAYLOAD],
            _ => &data[self.header_len()..],
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u16(&mut data[field::TYPE], value.into());
    }

    /// Set the message length field.
    #[inline]
    pub fn set_msg_len(&mut self, value: usize) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u16(&mut data[field::LEN], value as u16);
    }

    /// Set the sequence number field.
    #[inline]
    pub fn set_seq_num(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u16(&mut data[field::SEQ_NUM], value);
    }

    /// Set the reference number field.
    #[inline]
    pub fn set_ref_num(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        LittleEndian::write_u16(&mut data[field::REF_NUM], value);
    }

    /// Set the return value field.
    #[inline]
    pub fn set_ret(&mut self, value: Status) {
        let data = self.buffer.as_mut();
        LittleEndian::write_i16(&mut data[field::RET], value.into());
    }

    /// Clear any reserved fields in the message header.
    #[inline]
    pub fn clear_reserved(&mut self) {
        match self.msg_type() {
            Message::RxPacket => {
                let data = self.buffer.as_mut();
                data[field::RESERVED].copy_from_slice(&[0, 0]);
                data[field::RX_RESERVED].copy_from_slice(&[0u8; 16]);
            }
            Message::TxPacket => {
                let data = self.buffer.as_mut();
                data[field::RESERVED].copy_from_slice(&[0, 0]);
                data[field::TX_RESERVED_1] = 0;
                data[field::TX_RESERVED_2].copy_from_slice(&[0, 0]);
            }
            Message::RadioACfg | Message::RadioBCfg => {
                let data = self.buffer.as_mut();
                data[field::RESERVED].copy_from_slice(&[0, 0]);
                data[field::CFG_CLOCK_FREQ].copy_from_slice(&[0, 0]);
            }
            _ => {}
        }
    }

    /// Return a mutable pointer to the type-specific data.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

/// A high-level representation of an NXP LLC header.
#[derive(Debug, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Repr {
    TxPacket(TxPacketRepr),
    RxPacket(RxPacketRepr),
    RadioACfg(RadioConfigRepr),
    RadioBCfg(RadioConfigRepr),
}

impl Repr {
    /// Parse an NXP LLC header and return
    /// a high-level representation.
    pub fn parse<T>(llc: &Header<&T>) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        llc.check_len()?;

        match llc.msg_type() {
            Message::RxPacket => RxPacketRepr::parse(llc).map(Repr::RxPacket),
            Message::RadioACfg => RadioConfigRepr::parse(llc).map(Repr::RadioACfg),
            Message::RadioBCfg => RadioConfigRepr::parse(llc).map(Repr::RadioBCfg),
            _ => Err(Error),
        }
    }
}
