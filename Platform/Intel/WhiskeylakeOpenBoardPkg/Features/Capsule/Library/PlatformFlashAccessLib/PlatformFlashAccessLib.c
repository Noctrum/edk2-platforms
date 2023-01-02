/** @file
  Platform Flash Access library.

  Copyright (c) 2016 - 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Uefi.h>

#include <PiDxe.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/PlatformFlashAccessLib.h>
//#include <Library/FlashDeviceLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/Spi.h>
#include <Library/CacheMaintenanceLib.h>
//#include "PchAccess.h"
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>

//#include <Library/SpiFlashCommonLib.h>
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

//#define SECTOR_SIZE_64KB  0x10000      // Common 64kBytes sector size
//#define ALINGED_SIZE  SECTOR_SIZE_64KB

#define BLOCK_SIZE 0x1000
#define ALINGED_SIZE BLOCK_SIZE

#define R_PCH_LPC_BIOS_CNTL                       0xDC
#define B_PCH_LPC_BIOS_CNTL_SMM_BWP               0x20            ///< SMM BIOS write protect disable

//
// Prefix Opcode Index on the host SPI controller
//
typedef enum {
  SPI_WREN,             // Prefix Opcode 0: Write Enable
  SPI_EWSR,             // Prefix Opcode 1: Enable Write Status Register
} PREFIX_OPCODE_INDEX;
//
// Opcode Menu Index on the host SPI controller
//
typedef enum {
  SPI_READ_ID,        // Opcode 0: READ ID, Read cycle with address
  SPI_READ,           // Opcode 1: READ, Read cycle with address
  SPI_RDSR,           // Opcode 2: Read Status Register, No address
  SPI_WRDI_SFDP,      // Opcode 3: Write Disable or Discovery Parameters, No address
  SPI_SERASE,         // Opcode 4: Sector Erase (4KB), Write cycle with address
  SPI_BERASE,         // Opcode 5: Block Erase (32KB), Write cycle with address
  SPI_PROG,           // Opcode 6: Byte Program, Write cycle with address
  SPI_WRSR,           // Opcode 7: Write Status Register, No address
} SPI_OPCODE_INDEX;

STATIC EFI_PHYSICAL_ADDRESS     mInternalFdAddress;

SPI_INSTANCE  *mSpiInstance;
PCH_SPI_PROTOCOL  *mSpiProtocol;


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

//##########################################
#define SECTOR_SIZE_4KB   0x1000
/**
  Enable block protection on the Serial Flash device.

  @retval     EFI_SUCCESS       Opertion is successful.
  @retval     EFI_DEVICE_ERROR  If there is any device errors.

**/
EFI_STATUS
EFIAPI
SpiFlashLock (
  VOID
  )
{
  return EFI_SUCCESS;
}

/**
  Read NumBytes bytes of data from the address specified by
  PAddress into Buffer.

  @param[in]      Address       The starting physical address of the read.
  @param[in,out]  NumBytes      On input, the number of bytes to read. On output, the number
                                of bytes actually read.
  @param[out]     Buffer        The destination data buffer for the read.

  @retval         EFI_SUCCESS       Opertion is successful.
  @retval         EFI_DEVICE_ERROR  If there is any device errors.

**/
EFI_STATUS
EFIAPI
SpiFlashRead (
  IN     UINTN                        Address,
  IN OUT UINT32                       *NumBytes,
     OUT UINT8                        *Buffer
  )
{
  ASSERT ((NumBytes != NULL) && (Buffer != NULL));
  if ((NumBytes == NULL) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // This function is implemented specifically for those platforms
  // at which the SPI device is memory mapped for read. So this
  // function just do a memory copy for Spi Flash Read.
  //
  CopyMem (Buffer, (VOID *) Address, *NumBytes);

  return EFI_SUCCESS;
}

/**
  Write NumBytes bytes of data from Buffer to the address specified by
  PAddresss.

  @param[in]      Address         The starting physical address of the write.
  @param[in,out]  NumBytes        On input, the number of bytes to write. On output,
                                  the actual number of bytes written.
  @param[in]      Buffer          The source data buffer for the write.

  @retval         EFI_SUCCESS       Opertion is successful.
  @retval         EFI_DEVICE_ERROR  If there is any device errors.

**/
EFI_STATUS
EFIAPI
SpiFlashWrite (
  IN     UINTN                      Address,
  IN OUT UINT32                     *NumBytes,
  IN     UINT8                      *Buffer
  )
{
  EFI_STATUS                Status;
  UINTN                     Offset;
  UINT32                    Length;
  UINT32                    RemainingBytes;

  ASSERT ((NumBytes != NULL) && (Buffer != NULL));
  if ((NumBytes == NULL) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ASSERT (Address >= (UINTN)PcdGet32(PcdFlashAreaBaseAddress));

  Offset = Address - (UINTN)PcdGet32(PcdFlashAreaBaseAddress);

  ASSERT ((*NumBytes + Offset) <= (UINTN)PcdGet32(PcdFlashAreaSize));

  Status = EFI_SUCCESS;
  RemainingBytes = *NumBytes;


  while (RemainingBytes > 0) {
    if (RemainingBytes > SECTOR_SIZE_4KB) {
      Length = SECTOR_SIZE_4KB;
    } else {
      Length = RemainingBytes;
    }
    Status = mSpiProtocol->FlashWrite (
                             mSpiProtocol,
                             FlashRegionBios,
                             (UINT32) Offset,
                             Length,
                             Buffer
                             );
    if (EFI_ERROR (Status)) {
      break;
    }
    RemainingBytes -= Length;
    Offset += Length;
    Buffer += Length;
  }

  //
  // Actual number of bytes written
  //
  *NumBytes -= RemainingBytes;

  return Status;
}

/**
  Erase the block starting at Address.

  @param[in]  Address         The starting physical address of the block to be erased.
                              This library assume that caller garantee that the PAddress
                              is at the starting address of this block.
  @param[in]  NumBytes        On input, the number of bytes of the logical block to be erased.
                              On output, the actual number of bytes erased.

  @retval     EFI_SUCCESS.      Opertion is successful.
  @retval     EFI_DEVICE_ERROR  If there is any device errors.

**/
EFI_STATUS
EFIAPI
SpiFlashBlockErase (
  IN    UINTN                     Address,
  IN    UINTN                     *NumBytes
  )
{
  EFI_STATUS          Status;
  UINTN               Offset;
  UINTN               RemainingBytes;

  ASSERT (NumBytes != NULL);
  if (NumBytes == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ASSERT (Address >= (UINTN)PcdGet32(PcdFlashAreaBaseAddress));

  Offset = Address - (UINTN)PcdGet32(PcdFlashAreaBaseAddress);

  ASSERT ((*NumBytes % SECTOR_SIZE_4KB) == 0);
  ASSERT ((*NumBytes + Offset) <= (UINTN)PcdGet32(PcdFlashAreaSize));

  Status = EFI_SUCCESS;
  RemainingBytes = *NumBytes;


  Status = mSpiProtocol->FlashErase (
                           mSpiProtocol,
                           FlashRegionBios,
                           (UINT32) Offset,
                           (UINT32) RemainingBytes
                           );
  return Status;
}

//##########################################

EFI_STATUS
InternalReadBlock (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  OUT VOID                  *ReadBuffer
  )
{
  EFI_STATUS    Status;
  UINT32        BlockSize;

  BlockSize = BLOCK_SIZE;

  Status = SpiFlashRead ((UINTN) BaseAddress, &BlockSize, ReadBuffer);

  return Status;
}

/**

Routine Description:

  Erase the whole block.

Arguments:

  BaseAddress  - Base address of the block to be erased.

Returns:

  EFI_SUCCESS - The command completed successfully.
  Other       - Device error or wirte-locked, operation failed.

**/
EFI_STATUS
InternalEraseBlock (
  IN  EFI_PHYSICAL_ADDRESS BaseAddress
  )
{
  EFI_STATUS                              Status;
  UINTN                                   NumBytes;

  NumBytes = BLOCK_SIZE;

  Status = SpiFlashBlockErase ((UINTN) BaseAddress, &NumBytes);

  return Status;
}

EFI_STATUS
InternalCompareBlock (
  IN  EFI_PHYSICAL_ADDRESS        BaseAddress,
  IN  UINT8                       *Buffer
  )
{
  EFI_STATUS                              Status;
  VOID                                    *CompareBuffer;
  UINT32                                  NumBytes;
  INTN                                    CompareResult;

  NumBytes = BLOCK_SIZE;
  CompareBuffer = AllocatePool (NumBytes);
  if (CompareBuffer == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Status = SpiFlashRead ((UINTN) BaseAddress, &NumBytes, CompareBuffer);
  if (EFI_ERROR (Status)) {
    goto Done;
  }
  CompareResult = CompareMem (CompareBuffer, Buffer, BLOCK_SIZE);
  if (CompareResult != 0) {
    Status = EFI_VOLUME_CORRUPTED;
  }

Done:
  if (CompareBuffer != NULL) {
    FreePool (CompareBuffer);
  }

  return Status;
}

/**

Routine Description:

  Write a block of data.

Arguments:

  BaseAddress  - Base address of the block.
  Buffer       - Data buffer.
  BufferSize   - Size of the buffer.

Returns:

  EFI_SUCCESS           - The command completed successfully.
  EFI_INVALID_PARAMETER - Invalid parameter, can not proceed.
  Other                 - Device error or wirte-locked, operation failed.

**/
EFI_STATUS
InternalWriteBlock (
  IN  EFI_PHYSICAL_ADDRESS        BaseAddress,
  IN  UINT8                       *Buffer,
  IN  UINT32                      BufferSize
  )
{
  EFI_STATUS                              Status;

  Status = SpiFlashWrite ((UINTN) BaseAddress, &BufferSize, Buffer);

  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "\nFlash write error."));
    return Status;
  }

  WriteBackInvalidateDataCacheRange ((VOID *) (UINTN) BaseAddress, BLOCK_SIZE);

  Status = InternalCompareBlock (BaseAddress, Buffer);
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "\nError when writing to BaseAddress %x with different at offset %x.", BaseAddress, Status));
  } else {
    DEBUG((DEBUG_INFO, "\nVerified data written to Block at %x is correct.", BaseAddress));
  }

  return Status;

}

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
  EFI_STATUS            Status = EFI_SUCCESS;
  UINTN               Index;
  EFI_PHYSICAL_ADDRESS  Address;
  UINTN                 CountOfBlocks;
  EFI_TPL               OldTpl;
  BOOLEAN               FlashError;
  UINT8                 *Buf;
  //UINTN                 LpcBaseAddress;
  //UINT8                 Data8Or;
  //UINT8                 Data8And;
  //UINT8                 BiosCntl;

  Index             = 0;
  Address           = 0;
  CountOfBlocks     = 0;
  FlashError        = FALSE;
  Buf               = Buffer;

  DEBUG((DEBUG_INFO | DEBUG_ERROR, "PerformFlashWrite - 0x%x(%x) - 0x%x\n", (UINTN)FlashAddress, (UINTN)FlashAddressType, Length));
  if (FlashAddressType == FlashAddressTypeRelativeAddress) {
    FlashAddress = FlashAddress + mInternalFdAddress;
  }

  CountOfBlocks = (UINTN) (Length / BLOCK_SIZE);
  Address = FlashAddress;

  /*LpcBaseAddress = MmPciAddress (0,
                    DEFAULT_PCI_BUS_NUMBER_PCH,
                    PCI_DEVICE_NUMBER_PCH_LPC,
                    PCI_FUNCTION_NUMBER_PCH_LPC,
                    0
                    );
  BiosCntl = MmioRead8 (LpcBaseAddress + R_PCH_LPC_BIOS_CNTL);
  if ((BiosCntl & B_PCH_LPC_BIOS_CNTL_SMM_BWP) == B_PCH_LPC_BIOS_CNTL_SMM_BWP) {
    ///
    /// Clear SMM_BWP bit (D31:F0:RegDCh[5])
    ///
    Data8And  = (UINT8) ~B_PCH_LPC_BIOS_CNTL_SMM_BWP;
    Data8Or   = 0x00;

    MmioAndThenOr8 (
      LpcBaseAddress + R_PCH_LPC_BIOS_CNTL,
      Data8And,
      Data8Or
      );
    DEBUG((DEBUG_INFO, "PerformFlashWrite Clear SMM_BWP bit\n"));
  }*/

    //
    // Raise TPL to TPL_NOTIFY to block any event handler,
    // while still allowing RaiseTPL(TPL_NOTIFY) within
    // output driver during Print()
    //
    OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
    for (Index = 0; Index < CountOfBlocks; Index++) {
      if (Progress != NULL) {
        Progress (StartPercentage + ((Index * (EndPercentage - StartPercentage)) / CountOfBlocks));
      }
      //
      // Handle block based on address and contents.
      //
      if (!EFI_ERROR (InternalCompareBlock (Address, Buf))) {
        DEBUG((DEBUG_INFO, "Skipping block at 0x%lx (already programmed)\n", Address));
      } else {
        //
        // Make updating process uninterruptable,
        // so that the flash memory area is not accessed by other entities
        // which may interfere with the updating process
        //
        Status  = InternalEraseBlock (Address);
        if (EFI_ERROR(Status)) {
          gBS->RestoreTPL (OldTpl);
          FlashError = TRUE;
          goto Done;
        }
        Status = InternalWriteBlock (
                  Address,
                  Buf,
                  (UINT32)(Length > BLOCK_SIZE ? BLOCK_SIZE : Length)
                  );
        if (EFI_ERROR(Status)) {
          gBS->RestoreTPL (OldTpl);
          FlashError = TRUE;
          goto Done;
        }
      }

      //
      // Move to next block to update.
      //
      Address += BLOCK_SIZE;
      Buf += BLOCK_SIZE;
      if (Length > BLOCK_SIZE) {
        Length -= BLOCK_SIZE;
      } else {
        Length = 0;
      }
    }
    gBS->RestoreTPL (OldTpl);

Done:
  /*if ((BiosCntl & B_PCH_LPC_BIOS_CNTL_SMM_BWP) == B_PCH_LPC_BIOS_CNTL_SMM_BWP) {
    //
    // Restore original control setting
    //
    MmioWrite8 (LpcBaseAddress + R_PCH_LPC_BIOS_CNTL, BiosCntl);
  }*/

  if (Progress != NULL) {
    Progress (EndPercentage);
  }

  if (FlashError) {
    return EFI_WRITE_PROTECTED;
  }

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

/**
  Perform microcode write operation.

  @param[in] FlashAddress      The address of flash device to be accessed.
  @param[in] Buffer            The pointer to the data buffer.
  @param[in] Length            The length of data buffer in bytes.

  @retval EFI_SUCCESS           The operation returns successfully.
  @retval EFI_WRITE_PROTECTED   The flash device is read only.
  @retval EFI_UNSUPPORTED       The flash device access is unsupported.
  @retval EFI_INVALID_PARAMETER The input parameter is not valid.
**/
EFI_STATUS
EFIAPI
MicrocodeFlashWrite (
  IN EFI_PHYSICAL_ADDRESS         FlashAddress,
  IN VOID                         *Buffer,
  IN UINTN                        Length
  )
{
  EFI_PHYSICAL_ADDRESS         AlignedFlashAddress;
  VOID                         *AlignedBuffer;
  UINTN                        AlignedLength;
  UINTN                        OffsetHead;
  UINTN                        OffsetTail;
  EFI_STATUS                   Status;

  DEBUG((DEBUG_INFO, "MicrocodeFlashWrite - 0x%x - 0x%x\n", (UINTN)FlashAddress, Length));

  //
  // Need make buffer 64K aligned to support ERASE
  //
  // [Aligned]    FlashAddress    [Aligned]
  // |              |                     |
  // V              V                     V
  // +--------------+========+------------+
  // | OffsetHeader | Length | OffsetTail |
  // +--------------+========+------------+
  // ^
  // |<-----------AlignedLength----------->
  // |
  // AlignedFlashAddress
  //
  OffsetHead = FlashAddress & (ALINGED_SIZE - 1);
  OffsetTail = (FlashAddress + Length) & (ALINGED_SIZE - 1);
  if (OffsetTail != 0) {
    OffsetTail = ALINGED_SIZE - OffsetTail;
  }

  if ((OffsetHead != 0) || (OffsetTail != 0)) {
    AlignedFlashAddress = FlashAddress - OffsetHead;
    AlignedLength = Length + OffsetHead + OffsetTail;

    AlignedBuffer = AllocatePool(AlignedLength);
    if (AlignedBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    //
    // Save original buffer
    //
    if (OffsetHead != 0) {
      CopyMem((UINT8 *)AlignedBuffer, (VOID *)(UINTN)AlignedFlashAddress, OffsetHead);
    }
    if (OffsetTail != 0) {
      CopyMem((UINT8 *)AlignedBuffer + OffsetHead + Length, (VOID *)(UINTN)(AlignedFlashAddress + OffsetHead + Length), OffsetTail);
    }
    //
    // Override new buffer
    //
    CopyMem((UINT8 *)AlignedBuffer + OffsetHead, Buffer, Length);
  } else {
    AlignedFlashAddress = FlashAddress;
    AlignedBuffer = Buffer;
    AlignedLength = Length;
  }

  Status = PerformFlashWrite(
             PlatformFirmwareTypeSystemFirmware,
             AlignedFlashAddress,
             FlashAddressTypeAbsoluteAddress,
             AlignedBuffer,
             AlignedLength
             );
  if ((OffsetHead != 0) || (OffsetTail != 0)) {
    FreePool (AlignedBuffer);
  }
  return Status;
}


/*++

Routine Description:

  Entry point for the SPI host controller driver.


Returns:

  EFI_SUCCESS           Initialization complete.
  EFI_UNSUPPORTED       The chipset is unsupported by this driver.
  EFI_OUT_OF_RESOURCES  Do not have enough resources to initialize the driver.
  EFI_DEVICE_ERROR      Device error, driver exits abnormally.

--*/
EFI_STATUS
EFIAPI
InstallPchSpi (
  VOID
  )
{
  EFI_STATUS                      Status;
  //UINT64                          BaseAddress;
  //UINT64                          Length;
  //EFI_GCD_MEMORY_SPACE_DESCRIPTOR GcdMemorySpaceDescriptor;
  //UINT64                          Attributes;
  //EFI_EVENT                       Event;

  DEBUG ((DEBUG_INFO, "InstallPchSpi() Start\n"));

  //
  // Allocate Runtime memory for the SPI protocol instance.
  //
  mSpiInstance = AllocateRuntimeZeroPool (sizeof (SPI_INSTANCE));
  if (mSpiInstance == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  //
  // Initialize the SPI protocol instance
  //
  Status = SpiProtocolConstructor (mSpiInstance);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  //
  // Install the EFI_SPI_PROTOCOL interface
  //
  mSpiProtocol = &(mSpiInstance->SpiProtocol);

 /* Status = gBS->InstallMultipleProtocolInterfaces (
                  &(mSpiInstance->Handle),
                  &gEfiSpiProtocolGuid,
                  &(mSpiInstance->SpiProtocol),
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    FreePool (mSpiInstance);
    return EFI_DEVICE_ERROR;
  }
  //
  // Set RCBA space in GCD to be RUNTIME so that the range will be supported in
  // virtual address mode in EFI aware OS runtime.
  // It will assert if RCBA Memory Space is not allocated
  // The caller is responsible for the existence and allocation of the RCBA Memory Spaces
  //
  BaseAddress = (EFI_PHYSICAL_ADDRESS) (mSpiInstance->PchRootComplexBar);
  Length      = PcdGet64 (PcdRcbaMmioSize);

  Status      = gDS->GetMemorySpaceDescriptor (BaseAddress, &GcdMemorySpaceDescriptor);
  ASSERT_EFI_ERROR (Status);

  Attributes = GcdMemorySpaceDescriptor.Attributes | EFI_MEMORY_RUNTIME;

  Status = gDS->AddMemorySpace (
                  EfiGcdMemoryTypeMemoryMappedIo,
                  BaseAddress,
                  Length,
                  EFI_MEMORY_RUNTIME | EFI_MEMORY_UC
                  );
  ASSERT_EFI_ERROR(Status);

  Status = gDS->SetMemorySpaceAttributes (
                  BaseAddress,
                  Length,
                  Attributes
                  );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  PchSpiVirtualddressChangeEvent,
                  NULL,
                  &gEfiEventVirtualAddressChangeGuid,
                  &Event
                  );
  ASSERT_EFI_ERROR (Status);*/

  DEBUG ((DEBUG_INFO, "InstallPchSpi() End\n"));

  return EFI_SUCCESS;
}

/**
  Platform Flash Access Lib Constructor.
**/
EFI_STATUS
EFIAPI
PerformFlashAccessLibConstructor (
  VOID
  )
{
  EFI_STATUS Status;
  mInternalFdAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)PcdGet32(PcdFlashAreaBaseAddress);
  DEBUG((DEBUG_INFO, "PcdFlashAreaBaseAddress - 0x%x\n", mInternalFdAddress));

  /*Status = gBS->LocateProtocol (
                  &gPchSpiProtocolGuid, //tmp?
                  NULL,
                  (VOID **) &mSpiProtocol
                  );
  ASSERT_EFI_ERROR(Status);*/
  Status = InstallPchSpi();

  return EFI_SUCCESS;
}
