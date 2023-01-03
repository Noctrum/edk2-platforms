/** @file

  Copyright (c) 2004  - 2019, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:


  BootMode.c

Abstract:

  EFI PEIM to provide the platform support functionality on the Thurley.


--*/
#include "CommonHeader.h"
#include "Platform.h"

//
// Priority of our boot modes, highest priority first
//
EFI_BOOT_MODE mBootModePriority[] = {
  BOOT_IN_RECOVERY_MODE,
  BOOT_WITH_DEFAULT_SETTINGS,
  BOOT_ON_FLASH_UPDATE,
  BOOT_ON_S2_RESUME,
  BOOT_ON_S3_RESUME,
  BOOT_ON_S4_RESUME,
  BOOT_WITH_MINIMAL_CONFIGURATION,
  BOOT_ASSUMING_NO_CONFIGURATION_CHANGES,
  BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS,
  BOOT_WITH_FULL_CONFIGURATION,
  BOOT_ON_S5_RESUME
};

EFI_PEI_NOTIFY_DESCRIPTOR mCapsuleNotifyList[1] = {
  {
    (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
    &gPeiCapsulePpiGuid,
    CapsulePpiNotifyCallback
  }
};



EFI_STATUS
EFIAPI
CapsulePpiNotifyCallback (
  IN EFI_PEI_SERVICES           **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  )
{
  EFI_STATUS      Status;
  EFI_BOOT_MODE   BootMode;
  PEI_CAPSULE_PPI *Capsule;

  Status = (*PeiServices)->GetBootMode((const EFI_PEI_SERVICES **)PeiServices, &BootMode);
  ASSERT_EFI_ERROR (Status);

  if (BootMode == BOOT_ON_S3_RESUME) {
    //
    // Determine if we're in capsule update mode
    //
    Status = (*PeiServices)->LocatePpi ((const EFI_PEI_SERVICES **)PeiServices,
                                        &gPeiCapsulePpiGuid,
                                        0,
                                        NULL,
                                        (VOID **)&Capsule
                                        );

    if (Status == EFI_SUCCESS) {
      if (Capsule->CheckCapsuleUpdate ((EFI_PEI_SERVICES**)PeiServices) == EFI_SUCCESS) {
        BootMode = BOOT_ON_FLASH_UPDATE;
        DEBUG ((DEBUG_ERROR, "Setting BootMode to BOOT_ON_FLASH_UPDATE\n"));
        Status = (*PeiServices)->SetBootMode((const EFI_PEI_SERVICES **)PeiServices, BootMode);
        ASSERT_EFI_ERROR (Status);
      }
    }
  }

  return Status;
}

EFI_STATUS
UpdateBootMode (
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS      Status;
  EFI_BOOT_MODE   BootMode;
  CHAR16          *strBootMode;

  //
  // Let's assume things are OK if not told otherwise
  //
  BootMode = BOOT_WITH_FULL_CONFIGURATION;

  Status = (*PeiServices)->NotifyPpi (PeiServices, &mCapsuleNotifyList[0]);

  Status = (*PeiServices)->GetBootMode(PeiServices, &BootMode);

  switch (BootMode) {
    case BOOT_WITH_FULL_CONFIGURATION:
      strBootMode = L"BOOT_WITH_FULL_CONFIGURATION";
      break;
    case BOOT_WITH_MINIMAL_CONFIGURATION:
      strBootMode = L"BOOT_WITH_MINIMAL_CONFIGURATION";
      break;
    case BOOT_ASSUMING_NO_CONFIGURATION_CHANGES:
      strBootMode = L"BOOT_ASSUMING_NO_CONFIGURATION_CHANGES";
      break;
    case BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS:
      strBootMode = L"BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS";
      break;
    case BOOT_WITH_DEFAULT_SETTINGS:
      strBootMode = L"BOOT_WITH_DEFAULT_SETTINGS";
      break;
    case BOOT_ON_S4_RESUME:
      strBootMode = L"BOOT_ON_S4_RESUME";
      break;
    case BOOT_ON_S5_RESUME:
      strBootMode = L"BOOT_ON_S5_RESUME";
      break;
    case BOOT_ON_S2_RESUME:
      strBootMode = L"BOOT_ON_S2_RESUME";
      break;
    case BOOT_ON_S3_RESUME:
      strBootMode = L"BOOT_ON_S3_RESUME";
      break;
    case BOOT_ON_FLASH_UPDATE:
      strBootMode = L"BOOT_ON_FLASH_UPDATE";
      break;
    case BOOT_IN_RECOVERY_MODE:
      strBootMode = L"BOOT_IN_RECOVERY_MODE";
      break;
    default:
      strBootMode = L"Unknown boot mode";
  } // switch (BootMode)

  DEBUG ((DEBUG_ERROR, "Setting BootMode to %s\n", strBootMode));
  Status = (*PeiServices)->SetBootMode(PeiServices, BootMode);
  ASSERT_EFI_ERROR (Status);

  return Status;
}

