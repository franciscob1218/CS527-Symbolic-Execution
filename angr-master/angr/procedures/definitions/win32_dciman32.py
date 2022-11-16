# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("dciman32.dll")
prototypes = \
    {
        # 
        'DCIOpenProvider': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        # 
        'DCICloseProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hdc"]),
        # 
        'DCICreatePrimary': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lplpSurface"]),
        # 
        'DCICreateOffscreen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimStruct({"dciInfo": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), "Draw": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetClipList": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetDestination": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCIOFFSCREEN", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "dwCompression", "dwRedMask", "dwGreenMask", "dwBlueMask", "dwWidth", "dwHeight", "dwDCICaps", "dwBitCount", "lplpSurface"]),
        # 
        'DCICreateOverlay': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"dciInfo": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), "dwChromakeyValue": SimTypeInt(signed=False, label="UInt32"), "dwChromakeyMask": SimTypeInt(signed=False, label="UInt32")}, name="DCIOVERLAY", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lpOffscreenSurf", "lplpSurface"]),
        # 
        'DCIEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "lprDst", "lprSrc", "lpFnCallback", "lpContext"]),
        # 
        'DCISetSrcDestClip': SimTypeFunction([SimTypePointer(SimStruct({"dciInfo": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), "Draw": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetClipList": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetDestination": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCIOFFSCREEN", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"rdh": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "iType": SimTypeInt(signed=False, label="UInt32"), "nCount": SimTypeInt(signed=False, label="UInt32"), "nRgnSize": SimTypeInt(signed=False, label="UInt32"), "rcBound": SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None)}, name="RGNDATAHEADER", pack=False, align=None), "Buffer": SimTypePointer(SimTypeBottom(label="CHAR"), offset=0)}, name="RGNDATA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "srcrc", "destrc", "prd"]),
        # 
        'WinWatchOpen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd"]),
        # 
        'WinWatchClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hWW"]),
        # 
        'WinWatchGetClipList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"rdh": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "iType": SimTypeInt(signed=False, label="UInt32"), "nCount": SimTypeInt(signed=False, label="UInt32"), "nRgnSize": SimTypeInt(signed=False, label="UInt32"), "rcBound": SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None)}, name="RGNDATAHEADER", pack=False, align=None), "Buffer": SimTypePointer(SimTypeBottom(label="CHAR"), offset=0)}, name="RGNDATA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWW", "prc", "size", "prd"]),
        # 
        'WinWatchDidStatusChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWW"]),
        # 
        'GetWindowRegionData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"rdh": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "iType": SimTypeInt(signed=False, label="UInt32"), "nCount": SimTypeInt(signed=False, label="UInt32"), "nRgnSize": SimTypeInt(signed=False, label="UInt32"), "rcBound": SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None)}, name="RGNDATAHEADER", pack=False, align=None), "Buffer": SimTypePointer(SimTypeBottom(label="CHAR"), offset=0)}, name="RGNDATA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "size", "prd"]),
        # 
        'GetDCRegionData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"rdh": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "iType": SimTypeInt(signed=False, label="UInt32"), "nCount": SimTypeInt(signed=False, label="UInt32"), "nRgnSize": SimTypeInt(signed=False, label="UInt32"), "rcBound": SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None)}, name="RGNDATAHEADER", pack=False, align=None), "Buffer": SimTypePointer(SimTypeBottom(label="CHAR"), offset=0)}, name="RGNDATA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hdc", "size", "prd"]),
        # 
        'WinWatchNotify': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hww", "hwnd", "code", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWW", "NotifyCallback", "NotifyParam"]),
        # 
        'DCIEndAccess': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pdci"]),
        # 
        'DCIBeginAccess': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "x", "y", "dx", "dy"]),
        # 
        'DCIDestroy': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["pdci"]),
        # 
        'DCIDraw': SimTypeFunction([SimTypePointer(SimStruct({"dciInfo": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), "Draw": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetClipList": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetDestination": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCIOFFSCREEN", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci"]),
        # 
        'DCISetClipList': SimTypeFunction([SimTypePointer(SimStruct({"dciInfo": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), "Draw": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetClipList": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetDestination": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCIOFFSCREEN", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"rdh": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "iType": SimTypeInt(signed=False, label="UInt32"), "nCount": SimTypeInt(signed=False, label="UInt32"), "nRgnSize": SimTypeInt(signed=False, label="UInt32"), "rcBound": SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None)}, name="RGNDATAHEADER", pack=False, align=None), "Buffer": SimTypePointer(SimTypeBottom(label="CHAR"), offset=0)}, name="RGNDATA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "prd"]),
        # 
        'DCISetDestination': SimTypeFunction([SimTypePointer(SimStruct({"dciInfo": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "dwDCICaps": SimTypeInt(signed=False, label="UInt32"), "dwCompression": SimTypeInt(signed=False, label="UInt32"), "dwMask": SimTypeFixedSizeArray(SimTypeInt(signed=False, label="UInt32"), 3), "dwWidth": SimTypeInt(signed=False, label="UInt32"), "dwHeight": SimTypeInt(signed=False, label="UInt32"), "lStride": SimTypeInt(signed=True, label="Int32"), "dwBitCount": SimTypeInt(signed=False, label="UInt32"), "dwOffSurface": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "wSelSurface": SimTypeShort(signed=False, label="UInt16"), "wReserved": SimTypeShort(signed=False, label="UInt16"), "dwReserved1": SimTypeInt(signed=False, label="UInt32"), "dwReserved2": SimTypeInt(signed=False, label="UInt32"), "dwReserved3": SimTypeInt(signed=False, label="UInt32"), "BeginAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "EndAccess": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "DestroySurface": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCISURFACEINFO", pack=False, align=None), "Draw": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetClipList": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "SetDestination": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="DCIOFFSCREEN", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"left": SimTypeInt(signed=True, label="Int32"), "top": SimTypeInt(signed=True, label="Int32"), "right": SimTypeInt(signed=True, label="Int32"), "bottom": SimTypeInt(signed=True, label="Int32")}, name="RECT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdci", "dst", "src"]),
    }

lib.set_prototypes(prototypes)
