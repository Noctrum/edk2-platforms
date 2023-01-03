/** @file

  Copyright (c) 2004  - 2019, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

Module Name:

**/

#include "CommonHeader.h"

#include "Platform.h"




/**
  This is the entrypoint of PEIM

  @param  FileHandle  Handle of the file being invoked.
  @param  PeiServices Describes the list of possible PEI Services.

  @retval EFI_SUCCESS if it completed successfully.
**/
EFI_STATUS
EFIAPI
PeiInitPlatform (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS                       Status= EFI_SUCCESS;

  //
  // Set the new boot mode for MRC
  //
  Status = UpdateBootMode (PeiServices);
  ASSERT_EFI_ERROR (Status);

  return Status;
}
