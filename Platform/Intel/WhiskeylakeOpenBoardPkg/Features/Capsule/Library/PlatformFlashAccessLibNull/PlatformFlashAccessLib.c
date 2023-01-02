/** @file
  Platform flash device access library NULL instance.

  Copyright (c) 2016 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Library/BaseMemoryLib.h>
#include <Library/PlatformFlashAccessLib.h>

//#include <Private/Library/PchSpiCommonLib.h>
//#include "PchSpiCommonLib.h"

//#include <PchReservedResources.h>

//#include <IndustryStandard/Pci30.h>
//#include <Register/PchRegs.h>
//#include <Register/PchRegsSpi.h>

#include <Library/IoLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/PciSegmentLib.h>
#include <Protocol/Spi.h>
#include <Protocol/SmmCpu.h>
#include <Private/Library/PchSpiCommonLib.h>
#include <Private/Library/SmmPchPrivateLib.h>
#include <PchReservedResources.h>
#include <IndustryStandard/Pci30.h>
#include <Register/PchRegs.h>
#include <Register/PchRegsSpi.h>


UINT64 mInternalFdAddress;

// AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
GLOBAL_REMOVE_IF_UNREFERENCED UINT32                mSpiResvMmioAddr = PCH_SPI_BASE_ADDRESS;
/**
  Acquire PCH spi mmio address.
  If it is ever different from the preallocated address, reassign it back.
  In SMM, it always override the BAR0 and returns the reserved MMIO range for SPI.

  @param[in] SpiInstance          Pointer to SpiInstance to initialize

  @retval PchSpiBar0              return SPI MMIO address
**/
UINTN
AcquireSpiBar0 (
  IN  SPI_INSTANCE                *SpiInstance
  )
{
  UINT32                          SpiBar0;
  //
  // Save original SPI physical MMIO address
  //
  SpiBar0 = PciSegmentRead32 (SpiInstance->PchSpiBase + R_SPI_CFG_BAR0) & ~(B_SPI_CFG_BAR0_MASK);

  if (SpiBar0 != mSpiResvMmioAddr) {
    //
    // Temporary disable MSE, and override with SPI reserved MMIO address, then enable MSE.
    //
    PciSegmentAnd8 (SpiInstance->PchSpiBase + PCI_COMMAND_OFFSET, (UINT8) ~EFI_PCI_COMMAND_MEMORY_SPACE);
    PciSegmentWrite32 (SpiInstance->PchSpiBase + R_SPI_CFG_BAR0, mSpiResvMmioAddr);
    PciSegmentOr8 (SpiInstance->PchSpiBase + PCI_COMMAND_OFFSET, EFI_PCI_COMMAND_MEMORY_SPACE);
  }
  //
  // SPIBAR0 will be different before and after PCI enum so need to get it from SPI BAR0 reg.
  //
  return mSpiResvMmioAddr;
}


/**
  Check if it's granted to do flash write.

  @retval TRUE    It's secure to do flash write.
  @retval FALSE   It's not secure to do flash write.
**/
BOOLEAN
IsSpiFlashWriteGranted (
  VOID
  )
{
  return TRUE;
}


/**
  Release pch spi mmio address. Do nothing.

  @param[in] SpiInstance          Pointer to SpiInstance to initialize

  @retval None
**/
VOID
ReleaseSpiBar0 (
  IN  SPI_INSTANCE                *SpiInstance
  )
{
}


/**
  This function is a hook for Spi to enable BIOS Write Protect


**/
VOID
EFIAPI
EnableBiosWriteProtect (
  VOID
  )
{
  UINT64     SpiBaseAddress;

  SpiBaseAddress = PCI_SEGMENT_LIB_ADDRESS (
                     DEFAULT_PCI_SEGMENT_NUMBER_PCH,
                     DEFAULT_PCI_BUS_NUMBER_PCH,
                     PCI_DEVICE_NUMBER_PCH_SPI,
                     PCI_FUNCTION_NUMBER_PCH_SPI,
                     0
                     );
  ///
  /// Clear BIOSWE bit (SPI PCI Offset DCh [0]) = 0b
  /// Disable the access to the BIOS space for write cycles
  ///
  PciSegmentAnd8 (
    SpiBaseAddress + R_SPI_CFG_BC,
    (UINT8) (~B_SPI_CFG_BC_WPD)
    );

  ///
  /// Check if EISS bit is set
  ///
  //FIXME: Noctrum
  //if (((PciSegmentRead8 (SpiBaseAddress + R_SPI_CFG_BC)) & B_SPI_CFG_BC_EISS) == B_SPI_CFG_BC_EISS) {
    //PchClearInSmmSts ();
  //}
}


/**
  This function is a hook for Spi to disable BIOS Write Protect

  @retval EFI_SUCCESS             The protocol instance was properly initialized
  @retval EFI_ACCESS_DENIED       The BIOS Region can only be updated in SMM phase

**/
EFI_STATUS
EFIAPI
DisableBiosWriteProtect (
  VOID
  )
{
  UINT64     SpiBaseAddress;

  SpiBaseAddress = PCI_SEGMENT_LIB_ADDRESS (
                     DEFAULT_PCI_SEGMENT_NUMBER_PCH,
                     DEFAULT_PCI_BUS_NUMBER_PCH,
                     PCI_DEVICE_NUMBER_PCH_SPI,
                     PCI_FUNCTION_NUMBER_PCH_SPI,
                     0
                     );
  // Write clear BC_SYNC_SS prior to change WPD from 0 to 1.
  //
  PciSegmentOr8 (
    SpiBaseAddress + R_SPI_CFG_BC + 1,
    (B_SPI_CFG_BC_SYNC_SS >> 8)
    );
  ///
  /// Set BIOSWE bit (SPI PCI Offset DCh [0]) = 1b
  /// Enable the access to the BIOS space for both read and write cycles
  ///
  PciSegmentOr8 (
    SpiBaseAddress + R_SPI_CFG_BC,
    B_SPI_CFG_BC_WPD
    );

  ///
  /// PCH BIOS Spec Section 3.7 BIOS Region SMM Protection Enabling
  /// If the following steps are implemented:
  ///  - Set the EISS bit (SPI PCI Offset DCh [5]) = 1b
  ///  - Follow the 1st recommendation in section 3.6
  /// the BIOS Region can only be updated by following the steps bellow:
  ///  - Once all threads enter SMM
  ///  - Read memory location FED30880h OR with 00000001h, place the result in EAX,
  ///    and write data to lower 32 bits of MSR 1FEh (sample code available)
  ///  - Set BIOSWE bit (SPI PCI Offset DCh [0]) = 1b
  ///  - Modify BIOS Region
  ///  - Clear BIOSWE bit (SPI PCI Offset DCh [0]) = 0b
  ///

  //FIXME: Noctrum
  //if ((PciSegmentRead8 (SpiBaseAddress + R_SPI_CFG_BC) & B_SPI_CFG_BC_EISS) != 0) {
    //PchSetInSmmSts ();
  //}

  return EFI_SUCCESS;
}


//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa


/**
  Perform flash write operation with progress indicator.  The start and end
  completion percentage values are passed into this function.  If the requested
  flash write operation is broken up, then completion percentage between the
  start and end values may be passed to the provided Progress function.  The
  caller of this function is required to call the Progress function for the
  start and end completion percentage values.  This allows the Progress,
  StartPercentage, and EndPercentage parameters to be ignored if the requested
  flash write operation can not be broken up

  @param[in] FirmwareType      The type of firmware.
  @param[in] FlashAddress      The address of flash device to be accessed.
  @param[in] FlashAddressType  The type of flash device address.
  @param[in] Buffer            The pointer to the data buffer.
  @param[in] Length            The length of data buffer in bytes.
  @param[in] Progress          A function used report the progress of the
                               firmware update.  This is an optional parameter
                               that may be NULL.
  @param[in] StartPercentage   The start completion percentage value that may
                               be used to report progress during the flash
                               write operation.
  @param[in] EndPercentage     The end completion percentage value that may
                               be used to report progress during the flash
                               write operation.

  @retval EFI_SUCCESS           The operation returns successfully.
  @retval EFI_WRITE_PROTECTED   The flash device is read only.
  @retval EFI_UNSUPPORTED       The flash device access is unsupported.
  @retval EFI_INVALID_PARAMETER The input parameter is not valid.
**/
EFI_STATUS
EFIAPI
PerformFlashWriteWithProgress (
  IN PLATFORM_FIRMWARE_TYPE                         FirmwareType,
  IN EFI_PHYSICAL_ADDRESS                           FlashAddress,
  IN FLASH_ADDRESS_TYPE                             FlashAddressType,
  IN VOID                                           *Buffer,
  IN UINTN                                          Length,
  IN EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS  Progress,        OPTIONAL
  IN UINTN                                          StartPercentage,
  IN UINTN                                          EndPercentage
  )
{
  if (FlashAddressType == FlashAddressTypeRelativeAddress) {
    FlashAddress = FlashAddress + mInternalFdAddress;
  }
  CopyMem((VOID *)(UINTN)(FlashAddress), Buffer, Length);
  return EFI_SUCCESS;
}

/**
  Perform flash write operation.

  @param[in] FirmwareType      The type of firmware.
  @param[in] FlashAddress      The address of flash device to be accessed.
  @param[in] FlashAddressType  The type of flash device address.
  @param[in] Buffer            The pointer to the data buffer.
  @param[in] Length            The length of data buffer in bytes.

  @retval EFI_SUCCESS           The operation returns successfully.
  @retval EFI_WRITE_PROTECTED   The flash device is read only.
  @retval EFI_UNSUPPORTED       The flash device access is unsupported.
  @retval EFI_INVALID_PARAMETER The input parameter is not valid.
**/
EFI_STATUS
EFIAPI
PerformFlashWrite (
  IN PLATFORM_FIRMWARE_TYPE       FirmwareType,
  IN EFI_PHYSICAL_ADDRESS         FlashAddress,
  IN FLASH_ADDRESS_TYPE           FlashAddressType,
  IN VOID                         *Buffer,
  IN UINTN                        Length
  )
{
  return PerformFlashWriteWithProgress (
           FirmwareType,
           FlashAddress,
           FlashAddressType,
           Buffer,
           Length,
           NULL,
           0,
           0
           );
}

