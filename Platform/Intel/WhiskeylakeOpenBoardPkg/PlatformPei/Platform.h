/*++

  Copyright (c) 2004  - 2019, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#ifndef __PEI_PLATFORM_H__
#define __PEI_PLATFORM_H__

#define PEI_STALL_RESOLUTION            1
#define STALL_PEIM_SIGNATURE   SIGNATURE_32('p','p','u','s')

typedef struct {
  UINT32                      Signature;
  EFI_FFS_FILE_HEADER         *FfsHeader;
  EFI_PEI_NOTIFY_DESCRIPTOR   StallNotify;
} STALL_CALLBACK_STATE_INFORMATION;

#define STALL_PEIM_FROM_THIS(a) CR (a, STALL_CALLBACK_STATE_INFORMATION, StallNotify, STALL_PEIM_SIGNATURE)

/**
  Peform the boot mode determination logic
  If the box is closed, then
  1. If it's first time to boot, it's boot with full config .
  2. If the ChassisIntrution is selected, force to be a boot with full config
  3. Otherwise it's boot with no change.

  @param  PeiServices General purpose services available to every PEIM.
  @param  BootMode The detected boot mode.

  @retval EFI_SUCCESS if the boot mode could be set
**/
EFI_STATUS
UpdateBootMode (
  IN CONST EFI_PEI_SERVICES     **PeiServices
  );


EFI_STATUS
EFIAPI
CapsulePpiNotifyCallback (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  );
#endif
