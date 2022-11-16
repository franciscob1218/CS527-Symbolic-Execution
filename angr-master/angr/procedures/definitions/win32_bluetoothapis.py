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
lib.set_library_names("bluetoothapis.dll")
prototypes = \
    {
        # 
        'BluetoothFindFirstRadio': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32")}, name="BLUETOOTH_FIND_RADIO_PARAMS", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pbtfrp", "phRadio"]),
        # 
        'BluetoothFindNextRadio': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind", "phRadio"]),
        # 
        'BluetoothFindRadioClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind"]),
        # 
        'BluetoothGetRadioInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "lmpSubversion": SimTypeShort(signed=False, label="UInt16"), "manufacturer": SimTypeShort(signed=False, label="UInt16")}, name="BLUETOOTH_RADIO_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pRadioInfo"]),
        # 
        'BluetoothFindFirstDevice': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "fReturnAuthenticated": SimTypeBottom(label="BOOL"), "fReturnRemembered": SimTypeBottom(label="BOOL"), "fReturnUnknown": SimTypeBottom(label="BOOL"), "fReturnConnected": SimTypeBottom(label="BOOL"), "fIssueInquiry": SimTypeBottom(label="BOOL"), "cTimeoutMultiplier": SimTypeChar(label="Byte"), "hRadio": SimTypeBottom(label="HANDLE")}, name="BLUETOOTH_DEVICE_SEARCH_PARAMS", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pbtsp", "pbtdi"]),
        # 
        'BluetoothFindNextDevice': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind", "pbtdi"]),
        # 
        'BluetoothFindDeviceClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hFind"]),
        # 
        'BluetoothGetDeviceInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi"]),
        # 
        'BluetoothUpdateDeviceRecord': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbtdi"]),
        # 
        'BluetoothRemoveDevice': SimTypeFunction([SimTypePointer(SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pAddress"]),
        # 
        'BluetoothSetServiceState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi", "pGuidService", "dwServiceFlags"]),
        # 
        'BluetoothEnumerateInstalledServices': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi", "pcServiceInout", "pGuidServices"]),
        # 
        'BluetoothEnableDiscovery': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio", "fEnabled"]),
        # 
        'BluetoothIsDiscoverable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio"]),
        # 
        'BluetoothEnableIncomingConnections': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio", "fEnabled"]),
        # 
        'BluetoothIsConnectable': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRadio"]),
        # 
        'BluetoothRegisterForAuthentication': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0)], SimTypeBottom(label="BOOL"), arg_names=["pvParam", "pDevice"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbtdi", "phRegHandle", "pfnCallback", "pvParam"]),
        # 
        'BluetoothRegisterForAuthenticationEx': SimTypeFunction([SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"deviceInfo": SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), "authenticationMethod": SimTypeInt(signed=False, label="BLUETOOTH_AUTHENTICATION_METHOD"), "ioCapability": SimTypeInt(signed=False, label="BLUETOOTH_IO_CAPABILITY"), "authenticationRequirements": SimTypeInt(signed=False, label="BLUETOOTH_AUTHENTICATION_REQUIREMENTS"), "Anonymous": SimUnion({"Numeric_Value": SimTypeInt(signed=False, label="UInt32"), "Passkey": SimTypeInt(signed=False, label="UInt32")}, name="<anon>", label="None")}, name="BLUETOOTH_AUTHENTICATION_CALLBACK_PARAMS", pack=False, align=None), offset=0)], SimTypeBottom(label="BOOL"), arg_names=["pvParam", "pAuthCallbackParams"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbtdiIn", "phRegHandleOut", "pfnCallbackIn", "pvParam"]),
        # 
        'BluetoothUnregisterAuthentication': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRegHandle"]),
        # 
        'BluetoothSendAuthenticationResponse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"dwSize": SimTypeInt(signed=False, label="UInt32"), "Address": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "ulClassofDevice": SimTypeInt(signed=False, label="UInt32"), "fConnected": SimTypeBottom(label="BOOL"), "fRemembered": SimTypeBottom(label="BOOL"), "fAuthenticated": SimTypeBottom(label="BOOL"), "stLastSeen": SimTypeBottom(label="SYSTEMTIME"), "stLastUsed": SimTypeBottom(label="SYSTEMTIME"), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 248)}, name="BLUETOOTH_DEVICE_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadio", "pbtdi", "pszPasskey"]),
        # 
        'BluetoothSendAuthenticationResponseEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"bthAddressRemote": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "authMethod": SimTypeInt(signed=False, label="BLUETOOTH_AUTHENTICATION_METHOD"), "Anonymous": SimUnion({"pinInfo": SimStruct({"pin": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16), "pinLength": SimTypeChar(label="Byte")}, name="BLUETOOTH_PIN_INFO", pack=False, align=None), "oobInfo": SimStruct({"C": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16), "R": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 16)}, name="BLUETOOTH_OOB_DATA_INFO", pack=False, align=None), "numericCompInfo": SimStruct({"NumericValue": SimTypeInt(signed=False, label="UInt32")}, name="BLUETOOTH_NUMERIC_COMPARISON_INFO", pack=False, align=None), "passkeyInfo": SimStruct({"passkey": SimTypeInt(signed=False, label="UInt32")}, name="BLUETOOTH_PASSKEY_INFO", pack=False, align=None)}, name="<anon>", label="None"), "negativeResponse": SimTypeChar(label="Byte")}, name="BLUETOOTH_AUTHENTICATE_RESPONSE", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadioIn", "pauthResponse"]),
        # 
        'BluetoothSdpGetElementData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"type": SimTypeInt(signed=False, label="SDP_TYPE"), "specificType": SimTypeInt(signed=False, label="SDP_SPECIFICTYPE"), "data": SimUnion({"int128": SimStruct({"LowPart": SimTypeLongLong(signed=False, label="UInt64"), "HighPart": SimTypeLongLong(signed=True, label="Int64")}, name="SDP_LARGE_INTEGER_16", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64"), "int32": SimTypeInt(signed=True, label="Int32"), "int16": SimTypeShort(signed=True, label="Int16"), "int8": SimTypeBottom(label="CHAR"), "uint128": SimStruct({"LowPart": SimTypeLongLong(signed=False, label="UInt64"), "HighPart": SimTypeLongLong(signed=False, label="UInt64")}, name="SDP_ULARGE_INTEGER_16", pack=False, align=None), "uint64": SimTypeLongLong(signed=False, label="UInt64"), "uint32": SimTypeInt(signed=False, label="UInt32"), "uint16": SimTypeShort(signed=False, label="UInt16"), "uint8": SimTypeChar(label="Byte"), "booleanVal": SimTypeChar(label="Byte"), "uuid128": SimTypeBottom(label="Guid"), "uuid32": SimTypeInt(signed=False, label="UInt32"), "uuid16": SimTypeShort(signed=False, label="UInt16"), "string": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_string_e__Struct", pack=False, align=None), "url": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_url_e__Struct", pack=False, align=None), "sequence": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_sequence_e__Struct", pack=False, align=None), "alternative": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_alternative_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="SDP_ELEMENT_DATA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pSdpStream", "cbSdpStreamLength", "pData"]),
        # 
        'BluetoothSdpGetContainerElementData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimStruct({"type": SimTypeInt(signed=False, label="SDP_TYPE"), "specificType": SimTypeInt(signed=False, label="SDP_SPECIFICTYPE"), "data": SimUnion({"int128": SimStruct({"LowPart": SimTypeLongLong(signed=False, label="UInt64"), "HighPart": SimTypeLongLong(signed=True, label="Int64")}, name="SDP_LARGE_INTEGER_16", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64"), "int32": SimTypeInt(signed=True, label="Int32"), "int16": SimTypeShort(signed=True, label="Int16"), "int8": SimTypeBottom(label="CHAR"), "uint128": SimStruct({"LowPart": SimTypeLongLong(signed=False, label="UInt64"), "HighPart": SimTypeLongLong(signed=False, label="UInt64")}, name="SDP_ULARGE_INTEGER_16", pack=False, align=None), "uint64": SimTypeLongLong(signed=False, label="UInt64"), "uint32": SimTypeInt(signed=False, label="UInt32"), "uint16": SimTypeShort(signed=False, label="UInt16"), "uint8": SimTypeChar(label="Byte"), "booleanVal": SimTypeChar(label="Byte"), "uuid128": SimTypeBottom(label="Guid"), "uuid32": SimTypeInt(signed=False, label="UInt32"), "uuid16": SimTypeShort(signed=False, label="UInt16"), "string": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_string_e__Struct", pack=False, align=None), "url": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_url_e__Struct", pack=False, align=None), "sequence": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_sequence_e__Struct", pack=False, align=None), "alternative": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_alternative_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="SDP_ELEMENT_DATA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pContainerStream", "cbContainerLength", "pElement", "pData"]),
        # 
        'BluetoothSdpGetAttributeValue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimStruct({"type": SimTypeInt(signed=False, label="SDP_TYPE"), "specificType": SimTypeInt(signed=False, label="SDP_SPECIFICTYPE"), "data": SimUnion({"int128": SimStruct({"LowPart": SimTypeLongLong(signed=False, label="UInt64"), "HighPart": SimTypeLongLong(signed=True, label="Int64")}, name="SDP_LARGE_INTEGER_16", pack=False, align=None), "int64": SimTypeLongLong(signed=True, label="Int64"), "int32": SimTypeInt(signed=True, label="Int32"), "int16": SimTypeShort(signed=True, label="Int16"), "int8": SimTypeBottom(label="CHAR"), "uint128": SimStruct({"LowPart": SimTypeLongLong(signed=False, label="UInt64"), "HighPart": SimTypeLongLong(signed=False, label="UInt64")}, name="SDP_ULARGE_INTEGER_16", pack=False, align=None), "uint64": SimTypeLongLong(signed=False, label="UInt64"), "uint32": SimTypeInt(signed=False, label="UInt32"), "uint16": SimTypeShort(signed=False, label="UInt16"), "uint8": SimTypeChar(label="Byte"), "booleanVal": SimTypeChar(label="Byte"), "uuid128": SimTypeBottom(label="Guid"), "uuid32": SimTypeInt(signed=False, label="UInt32"), "uuid16": SimTypeShort(signed=False, label="UInt16"), "string": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_string_e__Struct", pack=False, align=None), "url": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_url_e__Struct", pack=False, align=None), "sequence": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_sequence_e__Struct", pack=False, align=None), "alternative": SimStruct({"value": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "length": SimTypeInt(signed=False, label="UInt32")}, name="_alternative_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="SDP_ELEMENT_DATA", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRecordStream", "cbRecordLength", "usAttributeId", "pAttributeData"]),
        # 
        'BluetoothSdpGetString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"encoding": SimTypeShort(signed=False, label="UInt16"), "mibeNum": SimTypeShort(signed=False, label="UInt16"), "attributeId": SimTypeShort(signed=False, label="UInt16")}, name="SDP_STRING_TYPE_DATA", pack=False, align=None), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRecordStream", "cbRecordLength", "pStringData", "usStringOffset", "pszString", "pcchStringLength"]),
        # 
        'BluetoothSdpEnumAttributes': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="BOOL"), arg_names=["uAttribId", "pValueStream", "cbStreamSize", "pvParam"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSDPStream", "cbStreamSize", "pfnCallback", "pvParam"]),
        # 
        'BluetoothSetLocalServiceInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Enabled": SimTypeBottom(label="BOOL"), "btAddr": SimStruct({"Anonymous": SimUnion({"ullLong": SimTypeLongLong(signed=False, label="UInt64"), "rgBytes": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 6)}, name="<anon>", label="None")}, name="BLUETOOTH_ADDRESS", pack=False, align=None), "szName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 256), "szDeviceString": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 256)}, name="BLUETOOTH_LOCAL_SERVICE_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hRadioIn", "pClassGuid", "ulInstance", "pServiceInfoIn"]),
        # 
        'BluetoothIsVersionAvailable': SimTypeFunction([SimTypeChar(label="Byte"), SimTypeChar(label="Byte")], SimTypeInt(signed=True, label="Int32"), arg_names=["MajorVersion", "MinorVersion"]),
    }

lib.set_prototypes(prototypes)
