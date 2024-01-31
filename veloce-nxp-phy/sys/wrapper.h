#ifndef LLC_NO_BITFIELDS
#define LLC_NO_BITFIELDS
#endif

#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include "llc.h"

/// MAC frame type
typedef enum MacFrameType
{
  /// Managment (00)
  MAC_FRAME_TYPE_MGNT = 0x0,
  /// Control (01)
  MAC_FRAME_TYPE_CONTROL = 0x1,
  /// Data (10)
  MAC_FRAME_TYPE_DATA = 0x2
} eMacFrameType;
/// @copydoc eMacFrameType
typedef uint8_t tMacFrameType;

/// MAC frame subtype
typedef enum MacFrameSubType
{
  /// Management - Action
  MAC_FRAME_SUB_TYPE_ACTION = 0xD,
  /// Data - Data (non QoS)
  MAC_FRAME_SUB_TYPE_DATA = 0x0,
  /// Data - QoS Data
  MAC_FRAME_SUB_TYPE_QOS_DATA = 0x8
} eMacFrameSubType;
/// @copydoc eMacFrameSubType
typedef uint8_t tMacFrameSubType;

/// MAC Address
typedef uint8_t tMACAddr[6];

/// 802.11 sequence control bits
typedef union Dot4SeqCtrl
{
/*   struct
  {
#ifdef __LITTLE_ENDIAN_BITFIELD
    uint16_t FragmentNo:4; //Frame fragment number
    uint16_t SeqNo:12; //Frame sequence number
#else // __BIG_ENDIAN_BITFIELD
    uint16_t SeqNo :12; //Frame sequence number
    uint16_t FragmentNo :4; //Frame fragment number
#endif
  } Fields; */

  uint16_t SeqCtrl;
} __attribute__ ((packed)) tDot4SeqCtrl;

/// 802.11 header frame control
typedef union Dot4FrameCtrl
{
/*   struct
  {
#ifdef __LITTLE_ENDIAN_BITFIELD
    /// Protocol version. Currently 0
    uint16_t ProtocolVer:2;
    /// Type -00 management frame 01-control frame,10-Data frame
    uint16_t Type:2;
    /// Subtype
    uint16_t SubType:4;
    /// To the distribution system
    uint16_t ToDS: 1;
    /// Exit from the distribution system
    uint16_t FromDS: 1;
    /// more fragment frames to follow (last or unfragmented frame=0)
    uint16_t MoreFrag: 1;
    /// This re-transmission
    uint16_t Retry: 1;
    /// Station in power save mode
    uint16_t PwrMgt: 1;
    /// Additional frames buffered for the destination address
    uint16_t MoreData: 1;
    /// 1= data processed with WEP algorithm 0= no WEP
    uint16_t WEP: 1;
    /// Frames must be strictly ordered
    uint16_t Order: 1;
#else // __BIG_ENDIAN_BITFIELD
    /// Frames must be strictly ordered
    uint16_t Order :1;
    /// 1= data processed with WEP algorithm 0= no WEP
    uint16_t WEP :1;
    /// Additional frames buffered for the destination address
    uint16_t MoreData :1;
    /// Station in power save mode
    uint16_t PwrMgt :1;
    /// This re-transmission
    uint16_t Retry :1;
    /// more fragment frames to follow (last or unfragmented frame=0)
    uint16_t MoreFrag :1;
    /// Exit from the distribution system
    uint16_t FromDS :1;
    /// To the distribution system
    uint16_t ToDS :1;
    /// Subtype
    uint16_t SubType :4;
    /// Type -00 management frame 01-control frame,10-Data frame
    uint16_t Type :2;
    /// Protocol version. Currently 0
    uint16_t ProtocolVer :2;
#endif
  } Fields; */

  uint16_t FrameCtrl;
} __attribute__ ((packed)) tDot4FrameCtrl;

/// 802.11 header QoS control
typedef union Dot4QoSCtrl
{
/*   struct
  {
#ifdef __LITTLE_ENDIAN_BITFIELD
    /// TID
    uint16_t TID:4;
    /// EOSP
    uint16_t EOSP:1;
    /// Ack Policy
    uint16_t AckPolicy:2;
    /// Reserved
    uint16_t Reserved:1;
    /// 'TXOP Duration Requested' or 'Queue size'
    uint16_t TXOPorQueue:8;
#else // __BIG_ENDIAN_BITFIELD
    /// 'TXOP Duration Requested' or 'Queue size'
    uint16_t TXOPorQueue :8;
    /// Reserved
    uint16_t Reserved :1;
    /// Ack Policy
    uint16_t AckPolicy :2;
    /// EOSP
    uint16_t EOSP :1;
    /// TID
    uint16_t TID :4;
#endif
  } Fields; */

  uint16_t QoSCtrl;
} __attribute__ ((packed)) tDot4QoSCtrl;

/// 802.11 MAC header (for QoS data frames)
typedef struct IEEE80211QoSHeader
{
  /// Frame control info
  tDot4FrameCtrl FrameControl;
  /// Duration ID, for data frames= duration of frames
  uint16_t DurationId;
  /// SA Source address
  tMACAddr Address1;
  /// DA Destination address
  tMACAddr Address2;
  /// BSSID Receiving station address (destination wireless station)
  tMACAddr Address3;
  /// Sequence control info
  tDot4SeqCtrl SeqControl;
  /// QoS control info
  tDot4QoSCtrl QoSControl;

} __attribute__ ((packed)) tIEEE80211QoSHeader;

/// 802.11 MAC header
typedef struct IEEE80211Header
{
  /// Frame control info
  tDot4FrameCtrl FrameControl;
  /// Duration ID, for data frames= duration of frames
  uint16_t DurationId;
  /// SA Source address
  uint8_t Address1[6];
  /// DA Destination address
  uint8_t Address2[6];
  /// BSSID Receiving station address (destination wireless station)
  uint8_t Address3[6];
  /// Sequence control info
  tDot4SeqCtrl SeqControl;

} __attribute__ ((packed)) tIEEE80211Header;

/// 802.2 SNAP header
typedef struct SNAPHeader
{
  union
  {
    uint16_t EtherType; ///< Ether type (EPD)
    struct
    {
      uint8_t DSAP; ///< Destination service access point
      uint8_t SSAP; ///< Source service access point
    };
  };
  uint8_t Control; ///< Control field
  uint8_t OUI[3]; ///< OUI field of snap header
  uint16_t Type; ///< Ether type
} __attribute__ ((packed)) tSNAPHeader;
