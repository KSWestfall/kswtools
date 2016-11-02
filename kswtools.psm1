<#
KSWtools
4/7/2016
Author: Kyle Westfall
Version 0.0.5

Description:
KSWtools is a bunch of commands wrapped up in functions to make easy access and use of them.
It gives the user the ability get numerous amounts of information from a specified computer,
and also has tools to ping multiple system fast(pmsf) from a txt file of computer names and
put a pop up on the specified computer(Send-Message).

All of these tools can be called from the main PowerShell command line or by calling kswtools
with or without the -ComputerName switch, asking the user for input if it is not provided.

I personally have this script called in my $PROFILE script to have it automatically imported
by adding the following to $PROFILE(type "notepad $PROFILE" to access it).

# directory where my scripts are stored

$psdir="h:\scripts\profile scripts"

# load all 'autoload' scripts

Get-ChildItem "${psdir}\*.ps1" | %{.$_}


Write-Host "Custom PowerShell Environment Loaded"
However it can be imported manually by calling ". kswtools.ps1". I also have alias's assigned
to specific functions so that i can call them quicky. For instance i have uptime as an alias
for Get-PCUptime.

Credit given where credit due:
Douglas DeCamp produced the get-PendingReboots script that i incorperated into this script.
for more info on the script please see the Get-PendingReboot function.
.REMARKS

#>

# Ping Multiple Systems Fast. specify computer using .txt file with each computer on
# single line.

function pmsf {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=0)]
        [string[]]$ComputersToPing,
    [Parameter(Mandatory=$False)]
        [string]$OutputName,
    [Parameter(Mandatory=$False)]
        [int]$Timeout = 1000,
    [Parameter(Mandatory=$false)]
        [switch]$NameOnly=$False,
    [Parameter(Mandatory=$false)]
        [switch]$CurrentlyOn=$False
    )

    # switch statement used to determine what to do depending on the output desired.
    switch -wildcard ($ComputersToPing) {
        "*.txt" {$ComputerName = Get-Content $ComputersToPing} # parse text file
        "*.csv" {$ComputerName = Get-Content $ComputersToPing} # parse csv file
        Default {$ComputerName = $ComputersToPing}
    }

    # ping all of the devices
    $filter = 'Address="' + ($ComputerName -join """ and Timeout=$Timeout or Address=""") + """ and Timeout=$Timeout";
    $Output = Get-WmiObject -Class Win32_PingStatus -Filter $filter |
                Select-Object -Property Address, ProtocolAddress, ResponseTime, Timeout

    # switch statement used to output file to specified choice
    if ($NameOnly -and $CurrentlyOn) {
        $Output = $Output | where {$_.ProtocolAddress -like '*.*.*.*'} | select Address;
    }
    elseif ($NameOnly) {
        $Output = $Output | select Address;
    }
    elseif ($CurrentlyOn) {
        $Output = $Output | where {$_.ProtocolAddress -like '*.*.*.*'}; 
    }
   
    switch -wildcard ($OutputName) {
        "*.txt" { ,$Output | Set-Content $OutputName}
        "*.csv" { ,$Output | Export-Csv $OutputName }
        default { ,$Output }
    }
}

# Send-Message displays a message on the specified computer.
# example: Send-Message -ComputerName %computername% -Message %Message to be displayed%
function Send-Message {
    [CmdletBinding()]
    param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName,
    [Parameter(Mandatory=$True,Position=2)]
        [string]$Message,
    [Parameter(Mandatory=$False)]
        [string]$UserName = "*",
    [Parameter(Mandatory=$False)]
        [string]$Time = "1000000000"
    ) 
    process{
        $Computers = InputCheck $ComputerName;
        
        foreach ($Computer in $Computers) {
            Invoke-WmiMethod -Class Win32_Process -ComputerName $Computer -Name Create -ArgumentList "C:\Windows\System32\msg.exe $($UserName) /time:$($Time) $($Message)"
        }
    }
}; Set-Alias psm -Value Send-Message;

# retrieves serial number from the specified computer
function Get-PCSerial {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName;
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_BIOS | Select-Object SerialNumber | Format-List
    }
};Set-Alias pcs -Value Get-PCSerial;

# Retrieves printer information from the specified computer
function Get-PCPrinterInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName;
    
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_Printer | Select-Object DeviceID,DriverName, PortName | Format-List;
    }
}; Set-Alias pcpi Get-PCPrinterInfo;

# Retrieves the current user from the specified computer
function Get-PCCurrentUser {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName;
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_ComputerSystem | Format-Table @{Expression={$_.Username};Label="Current User"}
    }
}; Set-Alias pccu -Value Get-PCCurrentUser;

# Retrieves information about the currently installed OS on the specified computer
function Get-PCOSInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_OperatingSystem | Format-List @{Expression={$_.Caption};Label="OS Name"},SerialNumber,OSArchitecture;
    }
}; Set-Alias pcos -Value Get-PCOSInfo;

# System Information
function Get-PCSysInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_ComputerSystem | Format-List Name,Domain,Manufacturer,Model,SystemType;
    }
}; Set-Alias pcsys -Value Get-PCSysInfo;

# Add/Remove Programs
function Get-PCAddRemovePrograms {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
            [string[]]$ComputerName,
        [Parameter(Mandatory=$false)]
            [string]$OutputPath,
        [Parameter(Mandatory=$false)]
            [switch]$AsJob
    )
    $Computers = InputCheck $ComputerName;
    foreach ($Computer in $Computers) {
        Write-Verbose "This may take several minutes";
        if ($AsJob) {
            Start-Job -Name $Computer -ArgumentList $Computer,$OutputPath -ScriptBlock {
                $Programs = Get-WmiObject -computer $args[0] Win32_Product | Select-Object Name | sort Name;
                switch -wildcard ($args[1]) {
                    "*.txt" { $Programs | Set-Content "$Computer$args[1]"; }
                    "*.csv" { $Programs | Export-Csv "$Computer$args[1]"; }
                    default { $Programs | Format-Table -AutoSize; }
                }
            }
        }
        else {
            $Programs = Get-WmiObject -computer $Computer Win32_Product | Select-Object Name | sort Name;
            switch -wildcard ($OutputPath) {
                "*.txt" { $Programs | Set-Content $OutputPath }
                "*.csv" { $Programs | Export-Csv $OutputPath }
                default { $Programs | Format-Table -AutoSize}
            }        
        }
    }
}; Set-Alias pcarp -Value Get-PCAddRemovePrograms;

# Process Listx
function Get-PCListProcess {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_Process | Select-Object Caption,Handle | Sort-Object Caption | Format-Table
    }
}; Set-Alias pclp -Value Get-PCListServices;

# List Services
function Get-PCListServices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_Service | Select-Object Name,State,Status,StartMode,ProcessID, ExitCode | Sort-Object Name | Format-Table
    }
}; Set-Alias pcls -Value Get-PCListServices;

# USB information
function Get-PCUSBInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName;
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_USBControllerDevice | ForEach-Object{[wmi]($_.Dependent)} | Select-Object Caption, Manufacturer, DeviceID | Format-List
    }
}; Set-Alias pcui -Value Get-PCUSBInfo;

# Uptime
function Get-PCUptime {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        $wmi = Get-WmiObject -computer $Computer Win32_OperatingSystem
        $localdatetime = $wmi.ConvertToDateTime($wmi.LocalDateTime)
        $lastbootuptime = $wmi.ConvertToDateTime($wmi.LastBootUpTime)

        "Current Time:      $localdatetime"
        "Last Boot Up Time: $lastbootuptime"

        $uptime = $localdatetime - $lastbootuptime
        ""
        "Uptime: $uptime"
        ""
    }
}; Set-Alias pcut -Value Get-PCUptime;

# Disk Information
function Get-PCDiskInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        $wmi = Get-WmiObject -computer $Computer Win32_logicaldisk
        foreach($device in $wmi){
                Write-Host "Drive: " $device.name
                Write-Host -NoNewLine "Size: "; "{0:N2}" -f ($device.Size/1GB) + " GB"
                Write-Host -NoNewLine "FreeSpace: "; "{0:N2}" -f ($device.FreeSpace/1GB) + " GB"
                ""
        }
    }
}; Set-Alias pcdi -Value Get-PCDiskInfo;

# Memory Information
function Get-PCMemoryInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    
    foreach ($Computer in $Computers) {
        $wmi = Get-WmiObject -computer $Computer Win32_PhysicalMemory
        foreach($device in $wmi){
            Write-Host "Bank Label:     " $device.BankLabel
            Write-Host "Capacity:       " ($device.Capacity/1MB) "Mb"
            Write-Host "Data Width:     " $device.DataWidth
            Write-Host "Device Locator: " $device.DeviceLocator
            ""
        }
    }
}; Set-Alias pcmi -Value Get-PCMemoryInfo;

# Processor Info
function Get-PCProcessorInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        Get-WmiObject -computer $Computer Win32_Processor | Format-List Caption,Name,Manufacturer,ProcessorId,NumberOfCores,AddressWidth
    }
}; Set-Alias pcproc -Value Get-PCProcessorInfo;

# Monitor information
function Get-PCMonitorInfo {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName

    #Turn off Error Messages
    $ErrorActionPreference_Backup = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    foreach ($Computer in $Computers) {
        $keytype=[Microsoft.Win32.RegistryHive]::LocalMachine
        if($reg=[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($keytype,$Computer)){
            #Create Table To Hold Info
            $montable = New-Object system.Data.DataTable "Monitor Info"
            #Create Columns for Table
            $moncol1 = New-Object system.Data.DataColumn Name,([string])
            $moncol2 = New-Object system.Data.DataColumn Serial,([string])
            $moncol3 = New-Object system.Data.DataColumn Ascii,([string])
            #Add Columns to Table
            $montable.columns.add($moncol1)
            $montable.columns.add($moncol2)
            $montable.columns.add($moncol3)



            $regKey= $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\DISPLAY" )
            $HID = $regkey.GetSubKeyNames()
            foreach($HID_KEY_NAME in $HID){
                $regKey= $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\$HID_KEY_NAME" )
                $DID = $regkey.GetSubKeyNames()
                foreach($DID_KEY_NAME in $DID){
                    $regKey= $reg.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\$HID_KEY_NAME\\$DID_KEY_NAME\\Device Parameters" )
                    $EDID = $regKey.GetValue("EDID")
                    foreach($int in $EDID){
                        $EDID_String = $EDID_String+([char]$int)
                    }
                    #Create new row in table
                    $monrow=$montable.NewRow()

                    #MonitorName
                    $checkstring = [char]0x00 + [char]0x00 + [char]0x00 + [char]0xFC + [char]0x00
                    $matchfound = $EDID_String -match "$checkstring([\w ]+)"
                    if($matchfound){$monrow.Name = [string]$matches[1]} else {$monrow.Name = '-'}


                    #Serial Number
                    $checkstring = [char]0x00 + [char]0x00 + [char]0x00 + [char]0xFF + [char]0x00
                    $matchfound =  $EDID_String -match "$checkstring(\S+)"
                    if($matchfound){$monrow.Serial = [string]$matches[1]} else {$monrow.Serial = '-'}

                    #AsciiString
                    $checkstring = [char]0x00 + [char]0x00 + [char]0x00 + [char]0xFE + [char]0x00
                    $matchfound = $EDID_String -match "$checkstring([\w ]+)"
                    if($matchfound){$monrow.Ascii = [string]$matches[1]} else {$monrow.Ascii = '-'}


                    $EDID_String = ''

                    $montable.Rows.Add($monrow)
                }
            }
            $montable | select-object  -unique Serial,Name,Ascii | Where-Object {$_.Serial -ne "-"} | Format-Table
        } else {
            Write-Host "Access Denied - Check Permissions"
        }
        $ErrorActionPreference = $ErrorActionPreference_Backup #Reset Error Messages
    }
}; Set-Alias pcmon -Value Get-PCMonitorInfo;

function Get-PCBuildDate{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        ([WMI]'').ConvertToDateTime((Get-WmiObject -computer $Computer Win32_OperatingSystem).InstallDate);
    }
};Set-Alias pcbd -Value Get-PCBuildDate;

# Returns the pending reboots for a specfied computer
function Get-PendingReboot{
    <#
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2014 v4.1.74
	 Created on:   	1/13/2015 5:35 AM
	 Created by:   	Douglas DeCamp
	 Organization: 	Lakeland Regional Health Systems
	 Filename:    Get-PendingReboot.ps1
	===========================================================================
	DESCRIPTION
		Going beyond the registry and looking at other parameters which may prevent an installation of a software pacakage due to a pending reboot. These would include Windows Update,
		SCCM Client, Pending File Rename and more to be added as it discovered through the trial and error process....
	Running this script
		PARAMETER ComputerName
    		A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

			PARAMETER ErrorLog
   			 A single path to send error data to a log file.

		EXAMPLE
   			 PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize

                    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
   				 	-------- ----------- ------------- ------------ -------------- -------------- -------------
				    DC01           False         False                       False                        False
				    DC02           False         False                       False                        False
				    FS01           False         False                       False                        False

				    This example will capture the contents of C:\ServerList.txt and query the pending reboot
				    information from the systems contained in the file and display the output in a table. The
				    null values are by design, since these systems do not have the SCCM 2012 client installed,
				    nor was the PendingFileRenameOperations value populated.

		EXAMPLE
		    PS C:\> Get-PendingReboot

		    Computer       : WKS01
		    CBServicing    : False
		    WindowsUpdate  : True
		    CCMClient      : False
		    PendFileRename : False
		    PendFileRenVal :
		    RebootPending  : True

		    This example will query the local machine for pending reboot information.

		EXAMPLE
		    PS C:\> $Servers = Get-Content C:\Servers.txt
		    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation

		    This example will create a report that contains pending reboot information.

		EXAMPLE
			PS C:\> $Servers = Get-Content C:\Servers.txt
			PS C:\> Get-PendingReboot.ps1 -Computer $Servers | Format-List | Out-File C:\MyScriptOutput\test.txt

			This example will create a report that contains the pending reboot information and displays it in a list format along with the full path of any pending file renames.

			Computer       : WKSTATION1
			CBServicing    : False
			WindowsUpdate  : False
			CCMClientSDK   : True
			PendFileRename : True
			PendFileRenVal : {\??\C:\Config.Msi\37f72.rbf, , \??\C:\Config.Msi\37f82.rbf, ...}
			RebootPending  : True
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("CN", "Computer")]
        [String[]]$ComputerName = "$env:COMPUTERNAME",
        [String]$ErrorLog
    )

    Begin
    {
        # Adjusting ErrorActionPreference to stop on all errors, since using [Microsoft.Win32.RegistryKey]
        # does not have a native ErrorAction Parameter, this may need to be changed if used within another function.
        $TempErrAct = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
    }#End Begin Script Block
    Process
    {
        Foreach ($Computer in $ComputerName)
        {
            Try
            {
                # Setting pending values to false to cut down on the number of else statements
                $PendFileRename, $Pending, $SCCM = $false, $false, $false

                # Setting CBSRebootPend to null since not all versions of Windows has this value
                $CBSRebootPend = $null

                # Querying WMI for build version
                $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer

                # Making registry connection to the local/remote computer
                $RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine", $Computer)

                # If Vista/2008 & Above query the CBS Reg Key
                If ($WMI_OS.BuildNumber -ge 6001)
                {
                    $RegSubKeysCBS = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\").GetSubKeyNames()
                    $CBSRebootPend = $RegSubKeysCBS -contains "RebootPending"

                }#End If ($WMI_OS.BuildNumber -ge 6001)

                # Query WUAU from the registry
                $RegWUAU = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
                $RegWUAURebootReq = $RegWUAU.GetSubKeyNames()
                $WUAURebootReq = $RegWUAURebootReq -contains "RebootRequired"

                # Query PendingFileRenameOperations from the registry
                $RegSubKeySM = $RegCon.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager\")
                $RegValuePFRO = $RegSubKeySM.GetValue("PendingFileRenameOperations", $null)

                # Closing registry connection
                $RegCon.Close()

                # If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
                If ($RegValuePFRO)
                {
                    $PendFileRename = $true

                }#End If ($RegValuePFRO)

                # Determine SCCM 2012 Client Reboot Pending Status
                # To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
                $CCMClientSDK = $null
                $CCMSplat = @{
                    NameSpace = 'ROOT\ccm\ClientSDK'
                    Class = 'CCM_ClientUtilities'
                    Name = 'DetermineIfRebootPending'
                    ComputerName = $Computer
                    ErrorAction = 'SilentlyContinue'
                }
                $CCMClientSDK = Invoke-WmiMethod @CCMSplat
                If ($CCMClientSDK)
                {
                    If ($CCMClientSDK.ReturnValue -ne 0)
                    {
                        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"

                    }#End If ($CCMClientSDK -and $CCMClientSDK.ReturnValue -ne 0)

                    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending)
                    {
                        $SCCM = $true

                    }#End If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending)

                }#End If ($CCMClientSDK)
                Else
                {
                    $SCCM = $null
                }

                # If any of the variables are true, set $Pending variable to $true
                If ($CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
                {
                    $Pending = $true
                }#End If ($CBS -or $WUAU -or $PendFileRename)

                # Creating Custom PSObject and Select-Object Splat
                $SelectSplat = @{
                    Property = ('Computer', 'CBServicing', 'WindowsUpdate', 'CCMClientSDK', 'PendFileRename', 'PendFileRenVal', 'RebootPending')
                }
                New-Object -TypeName PSObject -Property @{
                    Computer = $WMI_OS.CSName
                    CBServicing = $CBSRebootPend
                    WindowsUpdate = $WUAURebootReq
                    CCMClientSDK = $SCCM
                    PendFileRename = $PendFileRename
                    PendFileRenVal = $RegValuePFRO
                    RebootPending = $Pending
                } | Select-Object @SelectSplat

            }#End Try

            Catch
            {
                Write-Warning "$Computer`: $_"

                # If $ErrorLog, log the file to a user specified location/path
                If ($ErrorLog)
                {
                    Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append

                }#End If ($ErrorLog)

            }#End Catch

        }#End Foreach ($Computer in $ComputerName)

    }#End Process

    End
    {
        # Resetting ErrorActionPref
        $ErrorActionPreference = $TempErrAct
    }#End End

    #End Function
}; Set-Alias gpr Get-PendingReboot;

# OU information
function Get-PCOU {
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        Get-ADComputer -Identity $Computer | Select-Object DistinguishedName;
    }
}; Set-Alias ou Get-PCOU;

function Open-Cdrive {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [string[]]$ComputerName
    )
    $Computers = InputCheck $ComputerName
    foreach ($Computer in $Computers) {
        Invoke-Item "\\$Computer\c$";
    }
}; Set-Alias ocd -Value Open-Cdrive;

# get battery info
Function Get-PCBatteryInfo
{
  [CmdletBinding()]
  [OutputType([Nullable])]
  Param
  (
    # Param1 help description
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        [string[]]$ComputerName
  )
    $Computers = InputCheck $ComputerName

    [array]$AvailabilityArray = "Other (1)",
    "Unknown (2)",
    "Running/Full Power (3)",
    "Warning (4)",
    "In Test (5)",
    "Not Applicable (6)",
    "Power Off (7)",
    "Off Line (8)",
    "Off Duty (9)",
    "Degraded (10)",
    "Not Installed (11)",
    "Install Error (12)",
    "Power Save - Unknown (13)",
    "Power Save - Low Power Mode (14)",
    "Power Save - Standby (15)",
    "Power Cycle (16)",
    "Power Save - Warning (17)",
    "Paused (18)",
    "Not Ready (19)",
    "Not Configured (20)",
    "Quiesced (21)"

    [array]$BatteryStatusArray = "Other (1)",
    "Unknown (2)",
    "Fully Charged (3)",
    "Low (4)",
    "Critical (5)",
    "Charging (6)",
    "Charging and High (7)",
    "Charging and Low (8)",
    "Charging and Critical (9)",
    "Undefined (10)",
    "Partially Charged (11)"

    ""
    foreach ($Computer in $Computers) {
        [array]$BattInfo = Get-WmiObject -ComputerName $Computer Win32_Battery | %{$_.Availability, $_.BatteryStatus, $_.EstimatedChargeRemaining, $_.Name};
        $AvailabilityArray[$BattInfo[0].ToString()]
        ""
        $BatteryStatusArray[$BattInfo[1].ToString()]
        ""
        "Estimated charge remaining: " + $BattInfo[2]
        ""
        "Battery type: " + $BattInfo[3]
        ""
        
    }
}

# interface functions
# Function used to run the menu for kswtools
function kswtools {
    Param(
        [Parameter(Mandatory=$True,Position=1)]
            [string]$ComputerName=$env:COMPUTERNAME
    )
    
    begin{
        
        # switch statement used for the menu
        function GetInfo {
            Clear-Host
            switch ($MenuSelection) {
                1{Get-PCCurrentUser $ComputerName; Pause; CheckHost;}
                2{Get-PCUptime $ComputerName; Pause; CheckHost;}
                3{Open-Cdrive $ComputerName; CheckHost;}
                4{Get-PCOSInfo $ComputerName; Pause; CheckHost;}
                5{Get-PCAddRemovePrograms $ComputerName; Pause; CheckHost;}
                6{Get-PCListProcess $ComputerName; Pause; CheckHost;}
                7{Get-PCListServices $ComputerName; Pause; CheckHost;}
                8{Get-PCBuildDate $ComputerName; ""; Pause; CheckHost;}
                9{Get-PCOU $ComputerName; ""; Pause; CheckHost;}
                10{Get-PCDiskInfo $ComputerName; Pause; CheckHost;}
                11{Get-PCSysInfo $ComputerName; Pause; CheckHost;}
                12{Get-PCSerial $ComputerName; Pause; CheckHost;}
                13{Get-PCUSBInfo $ComputerName; Pause; CheckHost;}
                14{Get-PCPrinterInfo $ComputerName; Pause; CheckHost;}
                15{Get-PCMemoryInfo $ComputerName; Pause; CheckHost;}
                16{Get-PCProcessorInfo $ComputerName; Pause; CheckHost;}
                17{Get-PCMonitorInfo $ComputerName; Pause; CheckHost;}
                18{Get-PendingReboot $ComputerName; Pause; CheckHost;}
                19{Restart-Computer $ComputerName -Force; "Restart Command Sent"; Pause; CheckHost;}
                20{Stop-Computer $ComputerName -Force; "Shutdown Command Sent"; Pause; CheckHost;}
                21{Send-Message $ComputerName; Pause; CheckHost;}
                22{Get-PCBatteryInfo $ComputerName; Pause; CheckHost;}
                23{pmsf; Pause; CheckHost;}
                c {Clear-Host $ComputerName="";GetCompName;}
                q {Clear-Host;}
                "exit" {Clear-Host;}
                Default {CheckHost}
            }
        }
        # Menu for kswtools
        function GetMenu {

                Clear-Host
            ""
            "        KSWtools         "
            ""
            "  $ComputerName ($pcip)"
            ""
            ""
            "1) Current User"
            "2) Uptime"
            "3) Open C$ on $ComputerName"
            ""
            "Software Info"
            "4)  OS Info"
            "5)  Add/Remove Program List"
            "6)  Processes List"
            "7)  Services List"
            "8)  Build Date"
            "9)  Get Computer's OU"
            ""
            "Hardware Info"
            "10) Disk Space"
            "11) System Info"
            "12) PC Serial Number"
            "13) USB Devices"
            "14) PC Printer Info"
            "15) Memory Info"
            "16) Processor Info"
            "17) Monitor Information"
            ""
            "18) Pending reboots. Script by Douglas DeCamp"
            "19) Reboot $ComputerName"
            "20) Shutdown $ComputerName"
            "21) Popup Message on $ComputerName"
            "22) Laptop Battery Information"
            ""
            "Other Commands"
            "23) Ping multiple systems fast. Requires .txt file."
            ""
            "C) Change Computer Name"
            "Q) Exit The program"
            ""
            $MenuSelection = Read-Host "Enter Selection"
            GetInfo
        }
        # function used to ask for computer name
        function GetCompName {
            $ComputerName = Read-Host "Please enter a computer name or IP"
            CheckHost;
        }

        # function used to check the computer before running the commands
        function CheckHost{
            $ping = Get-WmiObject Win32_PingStatus -filter "Address='$ComputerName'"
            if($ping.StatusCode -eq 0){$pcip=$ping.ProtocolAddress; GetMenu}
            else{Pause "Host $ComputerName down...Press any key to continue"; GetCompName}
        }
    }
    
    process{
        if($ComputerName){CheckHost}
        else{GetCompName}
    }
}

function InputCheck ($ComputerName) {
    switch -wildcard ($ComputerName) {
                "*.txt" {$Computers = Get-Content $ComputerName} # parse text file
                "*.csv" {$Computers = Get-Content $ComputerName} # parse csv file
                Default {$Computers = $ComputerName}
            }
    $Computers;
}

Export-ModuleMember -Function kswtools;
Export-ModuleMember -Function get-*, open-Cdrive, Send-Message, pmsf;