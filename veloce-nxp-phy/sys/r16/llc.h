// No doxygen 'group' header because this file is included by both user & kernel implmentations

//------------------------------------------------------------------------------
// Copyright (c) 2013 Cohda Wireless Pty Ltd
//------------------------------------------------------------------------------

#ifndef __LINUX__COHDA__LLC__LLC_H_
#define __LINUX__COHDA__LLC__LLC_H_

//------------------------------------------------------------------------------
// Included headers
//------------------------------------------------------------------------------

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/wait.h>
#include <stdint.h>
#endif
//#include "cohda/llc/llc-api.h"
#include "llc-api.h"

//------------------------------------------------------------------------------
// Macros & Constants
//------------------------------------------------------------------------------

/// LLC module major version number
#define LLC_VERSION_MAJOR (1)
/// LLC module minor version number
#define LLC_VERSION_MINOR (0)

/// netdev name of LLC module
#define LLC_NETDEV_NAME "cw-llc"
/// chardev name of LLC module
#define LLC_CHARDEV_NAME "/dev/cw-llc"

//------------------------------------------------------------------------------
// Type definitions
//------------------------------------------------------------------------------

/// Message numbering within a network interface's SIOCDEVPRIVATE range
typedef enum LLCIoMsgId
{
  // Stack -> LLC
  LLC_IOMSG_CONFIG   = 0,
  LLC_IOMSG_TXREQ    = 1,
  LLC_IOMSG_TXFLUSH  = 2,
  LLC_IOMSG_SETTSF   = 3,
  LLC_IOMSG_GETTSF   = 4,
  // LLC -> Stack
  LLC_IOMSG_MKX      = 10,
  LLC_IOMSG_TXCNF    = 11,
  LLC_IOMSG_RXALLOC  = 12,
  LLC_IOMSG_RXIND    = 13,
  LLC_IOMSG_NOTIFIND = 14,
  // LLC <-> Stack
  LLC_IOMSG_DEBUG    = 15,
} eLLCIoMsgId;

//------------------------------------------------------------------------------
// Function Prototypes
//------------------------------------------------------------------------------

/**
 * @brief Get (update) the latest MKx handle contents
 * @param pMKx MKx handle
 * @return MKXSTATUS_SUCCESS (0) or a negative error code @sa eMKxStatus
 *
 * Only accessible from userspace
 */
tMKxStatus MKx_Get(tMKx *pMKx);

/**
 * @brief Get a MKx interface file number (for use with select or poll)
 * @param pMKx MKx handle initialized with MKx_Init()
 * @return Positive fileno (0:65535) or a negative error code @sa eMKxStatus
 *
 * Only accessible from userspace
 */
int MKx_Fd(tMKx *pMKx);

/**
 * @brief Handle messages from the MKx interface
 * @param pMKx MKx handle initialized with MKx_Init()
 * @return MKXSTATUS_SUCCESS (0) or a negative error code @sa eMKxStatus
 *
 * Only accessible from userspace
 */
tMKxStatus MKx_Recv(tMKx *pMKx);


#endif // #ifndef __LINUX__COHDA__LLC__LLC_H_
