/** @file
  Copyright (c) 2021, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>
  Copyright (c) 2025, Ventana Micro Systems Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/DevicePath.h>
#include <Protocol/PciHostBridgeResourceAllocation.h>
#include <Protocol/PciIo.h>
#include <UniversalPayload/PciRootBridges.h>
#include <Guid/PciSegmentInfoGuid.h>
#include <Guid/UniversalPayloadBase.h>

#define ROOT_BRIDGE_SUPPORTS_DEFAULT  (EFI_PCI_IO_ATTRIBUTE_VGA_IO_16 | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_PALETTE_IO_16 | \
                                       EFI_PCI_IO_ATTRIBUTE_ISA_IO_16 | \
                                       EFI_PCI_IO_ATTRIBUTE_IDE_PRIMARY_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_MEMORY | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_PALETTE_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_ISA_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_ISA_MOTHERBOARD_IO)

/**
  Build memory map I/O range resource HOB using the
  base address and size.

  @param  MemoryBase     Memory map I/O base.
  @param  MemorySize     Memory map I/O size.
**/

STATIC
VOID
AddIoMemoryBaseSizeHob (
  EFI_PHYSICAL_ADDRESS  MemoryBase,
  UINT64                MemorySize
  )
{
  //Align to EFI_PAGE_SIZE
  MemorySize = ALIGN_VALUE (MemorySize, EFI_PAGE_SIZE);
  BuildResourceDescriptorHob (
    EFI_RESOURCE_MEMORY_MAPPED_IO,
    EFI_RESOURCE_ATTRIBUTE_PRESENT     |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_TESTED,
    MemoryBase,
    MemorySize
    );
}

/**
  Populate IO resources from FDT that not added to GCD by its
  driver in the DXE phase.

  @param  FdtBase       Fdt base address
  @param  Compatible    Compatible string
**/

STATIC
VOID
PopulateIoResources (
  VOID         *FdtBase,
  CONST CHAR8  *Compatible
  )
{
  UINT64  *Reg;
  INT32   Node, LenP;

  Node = FdtNodeOffsetByCompatible (FdtBase, -1, Compatible);
  while (Node != -FDT_ERR_NOTFOUND) {
    Reg = (UINT64 *)FdtGetProp (FdtBase, Node, "reg", &LenP);
    if (Reg) {
      ASSERT (LenP == (2 * sizeof (UINT64)));
      AddIoMemoryBaseSizeHob (SwapBytes64 (Reg[0]), SwapBytes64 (Reg[1]));
    }

    Node = FdtNodeOffsetByCompatible (FdtBase, Node, Compatible);
  }
}

/**
  Parse PCI root bridge node and build HOB used by DXE.

  @param  Fdt       Fdt base address
**/
STATIC
VOID
ParsePciRootBridge (
  IN VOID  *Fdt
  )
{
  INT32                               Node;
  UINT8                               RbIndex;
  UINT8                               RootBridgeCount;
  UINTN                               HobDataSize;
  UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES      *mPciRootBridgeInfo;
  UPL_PCI_SEGMENT_INFO_HOB            *mUplPciSegmentInfoHob;
  UINT32                              AddressCells;
  INT32                               TempLen;
  CONST FDT_PROPERTY                  *PropertyPtr;
  INT32                               Property;
  CONST CHAR8                         *TempStr;
  UINT32                              *Data32;
  UINT8                               Base;
  UINT32                              MemType;

  //
  // TODO: Don't hard-code root bridge count.
  //
  Node = FdtNodeOffsetByCompatible (Fdt, -1, "pci-host-ecam-generic");
  if (Node == -FDT_ERR_NOTFOUND) {
    return;
  }

  RbIndex         = 0;
  RootBridgeCount = 1;

  //
  // Create PCI Root Bridge Info Hob.
  //
  HobDataSize        = sizeof (UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES) + (RootBridgeCount * sizeof (UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGE));
  mPciRootBridgeInfo = BuildGuidHob (&gUniversalPayloadPciRootBridgeInfoGuid, HobDataSize);
  ASSERT (mPciRootBridgeInfo != NULL);
  if (mPciRootBridgeInfo == NULL) {
    return;
  }

  ZeroMem (mPciRootBridgeInfo, HobDataSize);
  mPciRootBridgeInfo->Header.Length    = (UINT16)HobDataSize;
  mPciRootBridgeInfo->Header.Revision  = UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES_REVISION;
  mPciRootBridgeInfo->Count            = RootBridgeCount;
  mPciRootBridgeInfo->ResourceAssigned = FALSE;

  HobDataSize           = sizeof (UPL_PCI_SEGMENT_INFO_HOB) + (RootBridgeCount * sizeof (UPL_SEGMENT_INFO));
  mUplPciSegmentInfoHob = BuildGuidHob (&gUplPciSegmentInfoHobGuid, HobDataSize);
  if (mUplPciSegmentInfoHob != NULL) {
    ZeroMem (mUplPciSegmentInfoHob, HobDataSize);
    mUplPciSegmentInfoHob->Header.Length   = (UINT16)HobDataSize;
    mUplPciSegmentInfoHob->Header.Revision = UNIVERSAL_PAYLOAD_PCI_SEGMENT_INFO_REVISION;
    mUplPciSegmentInfoHob->Count           = RootBridgeCount;
  }

  AddressCells = 3;
  PropertyPtr  = FdtGetProperty (Fdt, Node, "#address-cells", &TempLen);
  if ((PropertyPtr != NULL) && (TempLen > 0)) {
    AddressCells = Fdt32ToCpu (*(UINT32 *)PropertyPtr->Data);
  }

  for (Property = FdtFirstPropertyOffset (Fdt, Node); Property >= 0; Property = FdtNextPropertyOffset (Fdt, Property)) {
    PropertyPtr = FdtGetPropertyByOffset (Fdt, Property, &TempLen);
    TempStr     = FdtGetString (Fdt, Fdt32ToCpu (PropertyPtr->NameOffset), NULL);

    if (AsciiStrCmp (TempStr, "ranges") == 0) {
      DEBUG ((DEBUG_INFO, "  Found ranges Property TempLen (%08X), limit %x\n", TempLen, TempLen / sizeof (UINT32)));

      mPciRootBridgeInfo->RootBridge[RbIndex].AllocationAttributes = EFI_PCI_HOST_BRIDGE_COMBINE_MEM_PMEM | EFI_PCI_HOST_BRIDGE_MEM64_DECODE;
      mPciRootBridgeInfo->RootBridge[RbIndex].Supports             = ROOT_BRIDGE_SUPPORTS_DEFAULT;
      mPciRootBridgeInfo->RootBridge[RbIndex].PMemAbove4G.Base     = PcdGet64 (PcdPciReservedPMemAbove4GBBase);
      mPciRootBridgeInfo->RootBridge[RbIndex].PMemAbove4G.Limit    = PcdGet64 (PcdPciReservedPMemAbove4GBLimit);
      mPciRootBridgeInfo->RootBridge[RbIndex].PMem.Base            = PcdGet32 (PcdPciReservedPMemBase);
      mPciRootBridgeInfo->RootBridge[RbIndex].PMem.Limit           = PcdGet32 (PcdPciReservedPMemLimit);
      mPciRootBridgeInfo->RootBridge[RbIndex].UID                  = RbIndex;
      mPciRootBridgeInfo->RootBridge[RbIndex].HID                  = EISA_PNP_ID (0x0A03);

      Data32 = (UINT32 *)(PropertyPtr->Data);
      for (Base = 0; Base < TempLen / sizeof (UINT32); Base += DWORDS_TO_NEXT_ADDR_TYPE) {
        DEBUG ((DEBUG_INFO, "  Base :%x \n", Base));
        MemType = Fdt32ToCpu (*(Data32 + Base));
        if (((MemType) & (SS_64BIT_MEMORY_SPACE)) == SS_64BIT_MEMORY_SPACE) {
          mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Base  = Fdt32ToCpu (*(Data32 + Base + 2)) + LShiftU64 (Fdt32ToCpu (*(Data32 + Base + 1)), 32);
          mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Limit = mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Base + LShiftU64 (Fdt32ToCpu (*(Data32 + Base + 5)), 32) + Fdt32ToCpu (*(Data32 + Base + 6)) - 1;
        } else if (((MemType) & (SS_32BIT_MEMORY_SPACE)) == SS_32BIT_MEMORY_SPACE) {
          mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Base  = Fdt32ToCpu (*(Data32 + Base + 2));
          mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Limit = mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Base + Fdt32ToCpu (*(Data32 + Base + 6)) - 1;
        } else if (((MemType) & (SS_IO_SPACE)) == SS_IO_SPACE) {
          mPciRootBridgeInfo->RootBridge[RbIndex].Io.Base  = Fdt32ToCpu (*(Data32 + Base + 2));
          mPciRootBridgeInfo->RootBridge[RbIndex].Io.Limit = mPciRootBridgeInfo->RootBridge[RbIndex].Io.Base + Fdt32ToCpu (*(Data32 + Base + 6)) - 1;
        }
      }

      DEBUG ((DEBUG_INFO, "RootBridgeCount %x, index :%x\n", RootBridgeCount, RbIndex));

      DEBUG ((DEBUG_INFO, "PciRootBridge->Mem.Base %x, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Base));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Mem.limit %x, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Limit));

      DEBUG ((DEBUG_INFO, "PciRootBridge->MemAbove4G.Base %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Base));
      DEBUG ((DEBUG_INFO, "PciRootBridge->MemAbove4G.limit %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Limit));

      DEBUG ((DEBUG_INFO, "PciRootBridge->Io.Base %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Io.Base));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Io.limit %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Io.Limit));
    }

    if ((AsciiStrCmp (TempStr, "reg") == 0) && (mUplPciSegmentInfoHob != NULL)) {
      UINT64  *Data64 = (UINT64 *)(PropertyPtr->Data);
      mUplPciSegmentInfoHob->SegmentInfo[RbIndex].BaseAddress = Fdt64ToCpu (ReadUnaligned64 (Data64));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Ecam.Base %llx, \n", mUplPciSegmentInfoHob->SegmentInfo[RbIndex].BaseAddress));
    }

    if (AsciiStrCmp (TempStr, "bus-range") == 0) {
      Data32                                                  = (UINT32 *)(PropertyPtr->Data);
      mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Base        = Fdt32ToCpu (*Data32) & 0xFF;
      mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Limit       = Fdt32ToCpu (*(Data32 + 1)) & 0xFF;
      mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Translation = 0;

      DEBUG ((DEBUG_INFO, "PciRootBridge->Bus.Base %x, index %x\n", mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Base, RbIndex));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Bus.limit %x, index %x\n", mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Limit, RbIndex));
    }
  }
}

#if 0

STATIC
VOID
HexDump (
  IN UINT8  *Data,
  IN UINTN  DataSize
  )
{
  for (UINTN Index = 0; Index < DataSize; Index++) {
    if (Index % 16 == 0) {
      DEBUG ((DEBUG_INFO, "\n"));
    }
    DEBUG ((DEBUG_INFO, "%02X ", Data[Index]));
  }
  DEBUG ((DEBUG_INFO, "\n"));
}

#endif

/**
  Perform Platform initialization.

  @param  FdtPointer      The pointer to the device tree.

  @return EFI_SUCCESS     The platform initialized successfully.
  @retval  Others        - As the error code indicates

**/
EFI_STATUS
EFIAPI
PlatformInitialization (
  VOID  *FdtPointer
  )
{
  VOID    *Base;
  VOID    *NewBase;
  UINTN   FdtSize;
  UINTN   FdtPages;
  UINT64  *FdtHobData;

  DEBUG ((DEBUG_INFO, "%a: Build FDT HOB - FDT at address: 0x%x \n", __func__, FdtPointer));
  Base = FdtPointer;
  if (FdtCheckHeader (Base) != 0) {
    DEBUG ((DEBUG_ERROR, "%a: Corrupted DTB\n", __func__));
    return EFI_UNSUPPORTED;
  }

  FdtSize  = FdtTotalSize (Base);
  FdtPages = EFI_SIZE_TO_PAGES (FdtSize);
  NewBase  = AllocatePages (FdtPages);
  if (NewBase == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: Could not allocate memory for DTB\n", __func__));
    return EFI_UNSUPPORTED;
  }

  //HexDump ((UINT8 *)Base, FdtSize);

  FdtOpenInto (Base, NewBase, EFI_PAGES_TO_SIZE (FdtPages));

  FdtHobData = BuildGuidHob (&gFdtHobGuid, sizeof *FdtHobData);
  if (FdtHobData == NULL) {
    DEBUG ((DEBUG_ERROR, "%a: Could not build FDT Hob\n", __func__));
    return EFI_UNSUPPORTED;
  }

  *FdtHobData = (UINTN)NewBase;

  PopulateIoResources (Base, "ns16550a");
  PopulateIoResources (Base, "pci-host-ecam-generic");
  ParsePciRootBridge (Base);
  return EFI_SUCCESS;
}
