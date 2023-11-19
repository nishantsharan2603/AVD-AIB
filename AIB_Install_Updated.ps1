$ErrorActionPreference = "stop"

$storageAccountName = "apsowvdstc05"
$storageAccountSas = "?sv=2022-11-02&ss=bfqt&srt=c&sp=rwdlacupiytfx&se=2023-11-18T00:45:02Z&st=2023-11-17T16:45:02Z&spr=https&sig=RJZPBjCt3hznYHN%2Fo29mwtPfjVG36%2FdfZL0qWhwfMq8%3D"
$storageAccounContainer = "source"

$uri = "https://$storageAccountName.blob.core.windows.net/$storageAccounContainer"
$OutputPath = "D:\"

#### Apps
$binaryGoogleChrome = "GoogleChromeStandaloneEnterprise64.msi"
$binaryJava32 = "Java_Runtime_Environment_(32bit)_v8_Update_241.exe"
$binaryJava64 = "Java_Runtime_Environment_(64bit)_v8_Update_241.exe"
$binaryJava132 ="jre1.8.0_202.msi"
$binaryJava164 ="jre1.8.0_20264.msi"
$binaryJava232 ="jre-8u121-windows-i586.exe"
$binaryJava264 ="jre-8u121-windows-x64.exe"
$binaryJava332 ="jre-8u141-windows-i586.exe"
$binaryJava364 ="jre-8u141-windows-x64.exe"
$binaryFSLogixJava ="FSLogixAppsJavaRuleEditorSetup.exe"
$binaryFSLogixMaskRule ="FSLogixAppsRuleEditorSetup.exe"
$binary7Zip ="7zip.exe"
$binaryRSAT="RSAT_FOD.zip"
$binaryCyberSafeTrustBrokerMSI = "CSTBscw-4.7.0-38896.Windows.x86_64.msi"
$binaryCyberSafeTrustBrokerMST = "CyberSafe_TrustBrokerSecureClientforWorkstations_4.7.0_R1_EN.Mst"
$binaryCyberSafeTrustBrokerLIC = "cstb.lic"
$binarySapTutorPlayerMSI="GBL_SAP_TutorPlayer_6400.210.0.0_R1_EN.msi"
$binarySapTutorPlayerMST="GBL_SAP_TutorPlayer_6400.210.0.0_R1_EN.Mst"
$binarySapTutorPlayervcred="vcredist_x86.msi"
$binaryDesktoplinkMSI = "desktop_link_21.1_64_bit.msi"
$binaryOpentextImageMSI="windows_viewer_21.1.msi"
$binaryOpentextImageMST="windows_viewer_21.1.Mst"
$binarySAPGUI="SAP_770.zip"
$binaryFACTMSI="FACT6.0_SAPINI_760_R1_EN.msi"
$binarySAPAFORedist="vstor_redist.exe"
$binarySAPAFO="AOFFICE28SP18_0-70004973.EXE"
$binarySAPAFORoamingConfig="Ao_user_roaming.config"
$binarySAPAFOVBS="AFO.vbs"
$binaryApacheJmeter="apache-jmeter-5.4.3.zip"
$binaryApacheJar="ojdbc8.jar"
$binaryFOD_LP="FOD_LP.zip"
$binaryPowerBI ="PBIDesktopSetup_x64.exe"
$binaryAdobe="Adobe.zip"
$binaryAdobeMSI="AcroRead.msi"
#$binaryAdobeMSP="AcroRdrDCUpd2200120117.msp"
$binaryAdobeMSP="AcroRdrDCUpd2300120143.msp"
$binarySilverLight ="Silverlight_x64.exe"
$binaryBrandCentral="BrandCentral.zip"
$binaryBrandCentralSetup ="Frontify-Setup-2.3.2.exe"
$binaryTabularEditor="TabularEditor.msi"
$binaryAIP="AzInfoProtection_UL.msi"
$binaryAsianfont="FontPack2200120085_XtdAlf_Lang_DC.msi"
$binaryDelineaPH="SSProtocolHandler.msi"
$binarymsoledbsql="msoledbsql.msi"
$binaryDelineaCMMSI="Delinea.ConnectionManager.WindowsInstaller.msi"
$binaryDelineaCMCONFIG="Delinea.ConnectionManager.exe.config"

### Functions
function Is-ProcessRunning([string] $ProcName)
{
    
    Start-Sleep -Seconds 5
        
    Is-ServiceRunning -ServiceName "Windows Installer"
    Get-RunningInstances -ProcName "msiexec"
    <#
    Get-Process | ForEach-Object { 
                                  Write-Host "[Is-ProcessRunning]  Process: $_"
                  }
    #>
	$Process = Get-Process | Where-Object {$_.Name -eq $ProcName}

    while ($Process.Count -ne 0)
    {

        Write-Host "[Is-ProcessRunning]  Process: $ProcName.exe is running."
        Start-Sleep -Seconds 5        
        Is-ServiceRunning -ServiceName "Windows Installer"
        Get-RunningInstances -ProcName "msiexec"
        Get-Process | ForEach-Object { 
                                  Write-Host "[Is-ProcessRunning]  Process: $_" 
                  }

                for ($i=0; $i -le 5; $i++) {
                    while ($true)
                    {
                        if (($IsMsiBusy = (Is-WindowsInstallerBusy -HandleWaitTime (New-TimeSpan -Seconds 30).TotalMilliseconds)) -eq $false)
                        {
                            Write-Host "[Is-ProcessRunning]  MsiMutexName: ""Global\_MSIExecute"" handle is NOT in use"                                
                            break;
                        }                                    
                    }
                    Start-Sleep 3
                }
        $Process = Get-Process | Where-Object {$_.Name -eq $ProcName}
    }

    for ($i=0; $i -le 5; $i++) {        
        $IsMsiBusy = $true
        while ($true)
        {    
            if (($IsMsiBusy = (Is-WindowsInstallerBusy -HandleWaitTime (New-TimeSpan -Seconds 30).TotalMilliseconds)) -eq $false)
            {
                Write-Host "[Is-ProcessRunning]  MsiMutexName: ""Global\_MSIExecute"" handle is NOT in use"                                
                break;
            }                                    
        }        
        if ($IsMsiBusy -eq $true) {Start-Sleep 5}else {Start-Sleep 2}
    }

   Write-Host "[Is-ProcessRunning]  Process: $ProcName.exe is NOT running." 

   return $false
}

function Is-ServiceRunning([string] $ServiceName)
{
    if (Get-Service | where {($_.DisplayName -eq "$ServiceName")-and ($_.Status -eq "Running")})
    {
        Write-Host "[Is-ServiceRunning] Service: $ServiceName is running..."
    }
}

function Get-RunningInstances([string] $ProcName)
{  
    Write-Host "[Get-RunningInstances]  Instances Running: $ProcName.exe = $(@(Get-Process $ProcName -ErrorAction 0).Count) "    
}

function Is-WindowsInstallerBusy{ param ([string] $MsiMutexName = "Global\_MSIExecute", 
                                [int32] $HandleWaitTime = 30000                                
                                )    
            
            [bool]$HandleException = $false            
            [bool]$IsMsiMutexBusy = $false
            [System.Timespan]$MutexWaitTime = [System.Timespan]::FromMilliseconds($HandleWaitTime)                     
            
            Write-Host "[Is-WindowsInstallerBusy]  Querying if MsiMutexName: ""$MsiMutexName"" is busy" 

            try {
                  [Threading.Mutex]$OpenMutexHandle = [Threading.Mutex]::OpenExisting($MsiMutexName)
                        try {
                            [string]$GetMsiParams = Get-WmiObject -Class 'Win32_Process' -Filter "name = 'msiexec.exe'" -ErrorAction 'Stop' | Where-Object { $_.CommandLine } | Select-Object -ExpandProperty 'CommandLine' | Where-Object { $_ -match '\.msi' } | ForEach-Object { $_.Trim() }
                            Write-Host "[Is-WindowsInstallerBusy]  MsiParams: The ""$GetMsiParams"" command line installaiton is in progress " 
                        }
                        catch {..}                                                
 
                  Write-Host "[Is-WindowsInstallerBusy]  WaitforMutexObject: Sleeping for $MutexWaitTime seconds" 
                  $IsMsiMutexBusy = $OpenMutexHandle.WaitOne($MutexWaitTime, $false)
            }
            Catch [Threading.WaitHandleCannotBeOpenedException],[ObjectDisposedException],[Threading.AbandonedMutexException] {                
                $IsMsiMutexBusy = $false
                Write-Host "[Is-WindowsInstallerBusy]  MsiMutexName: ""$MsiMutexName"" is available for use"                
            }
            Catch [UnauthorizedAccessException] {
                Write-Log -Level WARN -Message "[Is-WindowsInstallerBusy]  MsiMutexName: ""$MsiMutexName"" is NOT available for use"  
                $IsMsiMutexBusy = $false
            }
            Catch {
                $IsUnhandledException = $true                
                Write-Host "[Is-WindowsInstallerBusy]  MsiMutexName: ""$MsiMutexName"" is possibly available for use" 
                $IsMsiMutexBusy = $true
            }
            finally {
                    if ($IsMsiMutexBusy) {
                              try {
                                [string]$GetMsiParams = Get-WmiObject -Class 'Win32_Process' -Filter "name = 'msiexec.exe'" -ErrorAction 'Stop' | Where-Object { $_.CommandLine } | Select-Object -ExpandProperty 'CommandLine' | Where-Object { $_ -match '\.msi' } | ForEach-Object { $_.Trim() }
                                Write-Host "[Is-WindowsInstallerBusy]  MsiParams: The ""$GetMsiParams"" command line installaiton is in progress " 
                            }
                            catch {..}   
                    }
                }
                
                if (($NULL -ne $OpenMutexHandle) -and ($IsMsiMutexBusy)) {                    
                    $NULL = $OpenMutexHandle.ReleaseMutex()
                    $OpenMutexHandle.Close()
                    Write-Host "[Is-WindowsInstallerBusy]  MsiMutexName: ""$MsiMutexName"" handle released for use" 
                }                

            Write-Output -InputObject $IsMsiMutexBusy            
            return $IsMsiMutexBusy
}


### Install Apps

### Silverlight
Write-Host "downloading Silverlight ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binarySilverLight$storageAccountSas", "$OutputPath\$binarySilverLight")
Write-Host "installing Silverlight..."
Start-Process -FilePath  "$OutputPath\$binarySilverLight" -ArgumentList "/q /norestart"

### 7-Zip
Write-Host "downloading 7-Zip ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binary7Zip$storageAccountSas", "$OutputPath\$binary7Zip")
Write-Host "installing 7-Zip ..."
Start-Process -FilePath "$OutputPath\$binary7Zip" -ArgumentList '/S' -Wait

### Google Chrome
Write-Host "downloading Google Chrome ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryGoogleChrome$storageAccountSas", "$OutputPath\$binaryGoogleChrome")
Write-Host "installing Google Chrome ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\$binaryGoogleChrome /quiet /passive /norestart" -Wait
Is-ProcessRunning -ProcName "dummy"

### Java8_121_32Bit
Write-Host "downloading Java8_121_32Bit ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava232$storageAccountSas", "$OutputPath\$binaryJava232")
Write-Host "installing Java8_121_32Bit ..."
Start-Process -FilePath  "$OutputPath\$binaryJava232" -ArgumentList "/s" -PassThru -Wait

### Java8_121_64Bit
Write-Host "downloading Java8_121_64Bit ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava264$storageAccountSas", "$OutputPath\$binaryJava264")
Write-Host "installing Java8_121_64Bit ..."
Start-Process -FilePath  "$OutputPath\$binaryJava264" -ArgumentList "/s" -PassThru -Wait

### Java8_141_32Bit
Write-Host "downloading Java8_141_32Bit ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava332$storageAccountSas", "$OutputPath\$binaryJava332")
Write-Host "installing Java8_141_32Bit ..."
Start-Process -FilePath  "$OutputPath\$binaryJava332" -ArgumentList "/s" -PassThru -Wait

### Java8_141_64Bit
Write-Host "downloading Java8_141_64Bit ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava364$storageAccountSas", "$OutputPath\$binaryJava364")
Write-Host "installing Java8_141_64Bit ..."
Start-Process -FilePath  "$OutputPath\$binaryJava364" -ArgumentList "/s" -PassThru -Wait

### Java8_202_32Bit
Write-Host "Downloading Java8_202_32Bit..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava132$storageAccountSas", "$OutputPath\$binaryJava132")
Write-Host "installing Java8_202_32Bit ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\$binaryJava132 /qb" -Wait -Passthru

### Java8_202_64Bit
Write-Host "Downloading Java8_202_64Bit..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava164$storageAccountSas", "$OutputPath\$binaryJava164")
Write-Host "installing Java8_202_64Bit ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\$binaryJava164 /qb" -Wait -Passthru

### Java8_241_32Bit
Write-Host "downloading Java8_241_32Bit ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava32$storageAccountSas", "$OutputPath\$binaryJava32")
Write-Host "installing Java8_241_32Bit ..."
Start-Process -FilePath  "$OutputPath\$binaryJava32" -ArgumentList "/s" -PassThru -Wait

### Java8_241_64Bit
Write-Host "downloading Java8_241_64Bit ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryJava64$storageAccountSas", "$OutputPath\$binaryJava64")
Write-Host "installing Java8_241_32Bit ..."
Start-Process -FilePath  "$OutputPath\$binaryJava64" -ArgumentList "/s" -PassThru -Wait

### Azure Information Protect
Write-Host "downloading Azure Information Protect ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryAIP$storageAccountSas", "$OutputPath\$binaryAIP")
Write-Host "installing Azure Information Protect ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\$binaryAIP /quiet /passive /norestart" -Wait

### FSLogix AppMasking
Write-Host "Downloading FSLogix AppMask Setup"
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryFSLogixMaskRule$storageAccountSas", "$OutputPath\$binaryFSLogixMaskRule")
Write-Host "installing FSLogix AppMask Setup ..."
Start-Process -FilePath  "$OutputPath\$binaryFSLogixMaskRule" -ArgumentList "/s" -PassThru -Wait

### FSLogix JavaRuleSet
Write-Host "Downloading FSLogix JavaRuleSet ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryFSLogixJava$storageAccountSas", "$OutputPath\$binaryFSLogixJava")
Write-Host "installing FSLogix JavaRuleSet ..."
Start-Process -FilePath  "$OutputPath\$binaryFSLogixJava" -ArgumentList "/s" -PassThru -Wait

### PowerBI
Write-Host "downloading PowerBI ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryPowerBI$storageAccountSas", "$OutputPath\$binaryPowerBI")
Write-Host "installing PowerBI..."
Start-Process -FilePath  "$OutputPath\$binaryPowerBI" -ArgumentList " -s -norestart ACCEPT_EULA=1" -Wait
Is-ProcessRunning -ProcName "dummy"

###Intsalling RSAT
Write-Host "downloading RSAT ISO ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryRSAT$storageAccountSas", "$OutputPath\$binaryRSAT")
Write-Host "extracting RSAT ISO ..."
Expand-Archive -LiteralPath "$OutputPath\$binaryRSAT" -DestinationPath "$OutputPath\RSAT_ISO" -Force
Write-Host "installing RSAT  ..."
$RSAT_FOD1=Get-WindowsCapability -Online | Where-Object Name -like 'Rsat.ActiveDirectory.DS-LDS.Tools*'
$RSAT_FOD2=Get-WindowsCapability -Online | Where-Object Name -like 'Rsat.DHCP.Tools*'
$RSAT_FOD3=Get-WindowsCapability -Online | Where-Object Name -like 'Rsat.Dns.Tools*'
$RSAT_FOD4=Get-WindowsCapability -Online | Where-Object Name -like 'Rsat.GroupPolicy.Management.Tools*'
Add-WindowsCapability -Online -Name $RSAT_FoD1.name -Source "$OutputPath\RSAT_ISO\RSAT_FOD" -LimitAccess
Add-WindowsCapability -Online -Name $RSAT_FoD2.name -Source "$OutputPath\RSAT_ISO\RSAT_FOD" -LimitAccess
Add-WindowsCapability -Online -Name $RSAT_FoD3.name -Source "$OutputPath\RSAT_ISO\RSAT_FOD" -LimitAccess
Add-WindowsCapability -Online -Name $RSAT_FoD4.name -Source "$OutputPath\RSAT_ISO\RSAT_FOD" -LimitAccess
Write-Host "RSAT Tools Installed."

##Extracting SAP & its Component
(New-Object System.Net.WebClient).DownloadFile("$uri/$binarySAPGUI$storageAccountSas", "$OutputPath\$binarySAPGUI")
Write-Host "extracting SAP GUI ..."
Expand-Archive -LiteralPath "$OutputPath\$binarySAPGUI" -DestinationPath "$OutputPath\SAP_GUI" -Force

### CyberSafeTrustBroker
Write-Host "CyberSafeTrustBroker ..."
Write-Host "installing CyberSafeTrustBroker ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\SAP_GUI\SAP_770\CyberSafeTrustBroker_SAP_7.70_R1_EN\$binaryCyberSafeTrustBrokerMSI TRANSFORMS=$OutputPath\SAP_GUI\SAP_770\CyberSafeTrustBroker_SAP_7.70_R1_EN\$binaryCyberSafeTrustBrokerMST /qn" -Wait -Passthru
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\Credentials Manager" /v  "Applications" /t REG_SZ /d "CSTBcred32.exe" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\Key Table Management" /v "Applications" /t REG_SZ /d "ktutil.exe" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\CyberSafe\TrustBroker\Credentials Manager" /v "Applications" /t REG_SZ /d CSTBcred64.exe /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\CyberSafe\TrustBroker\Key Table Management" /v "Applications" /t REG_SZ /d "ktutil.exe" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI" /v "Applications" /t REG_SZ /d "sapgui.exe;saplogon.exe;saplgpad.exe;CSTBesigauth32.exe" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\GSS-API User Authentication" /v "Enable" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\GSS-API User Authentication" /v "ChangeCredentialsAfterLastActiveSession"  /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Kerberos" /v "CredCache"  /t REG_SZ /d "MSW:Default" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Sign-On" /v "AlwaysAuthenticateUser" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Sign-On" /v "UseLastAuthenticatedCredential"  /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Sign-On" /v "LockLastAuthenticatedCredential"  /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Sign-On" /v "AllowUserChangeAlwaysAuthenticateUser"  /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Sign-On" /v "WindowTitleSignOn" /t REG_SZ /d "CyberSafe TrustBroker Windows Secure SSO, for SAP GUI" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Sign-On" /v "WindowTitleChangePassword"  /t REG_SZ /d "CyberSafe TrustBroker Change Password, for SAP GUI" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Taskbar Notification Area" /v "ChangeSignOnApproach" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Kerberos" /v "AllowedAuthMethods"  /t REG_SZ /d "AD_Password" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\CyberSafe\TrustBroker\SAP GUI\Logging\Core" /v "Debug"  /t REG_DWORD /d 0  /f
Copy-Item -Path "$OutputPath\SAP_GUI\SAP_770\CyberSafeTrustBroker_SAP_7.70_R1_EN\$binaryCyberSafeTrustBrokerLIC" -Destination "C:\ProgramData\CyberSafe\license\"

###Sap Tutor Player
Write-Host "Sap Tutor Player ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\SAP_GUI\SAP_770\SAPTutorPlayer_SAP_7.70_R1_EN\$binarySapTutorPlayervcred /qn" -Wait -Passthru
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\SAP_GUI\SAP_770\SAPTutorPlayer_SAP_7.70_R1_EN\$binarySapTutorPlayerMSI TRANSFORMS=$OutputPath\SAP_GUI\SAP_770\SAPTutorPlayer_SAP_7.70_R1_EN\$binarySapTutorPlayerMST /qn" -Wait -Passthru


###Opentext Image
Write-Host "installing Opentext Image ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\SAP_GUI\SAP_770\OpenTextImage_SAP_7.70_R1_EN\$binaryOpentextImageMSI TRANSFORMS=$OutputPath\SAP_GUI\SAP_770\OpenTextImage_SAP_7.70_R1_EN\$binaryOpentextImageMST /qn" -Wait -Passthru
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\SAP_GUI\SAP_770\OpenTextImage_SAP_7.70_R1_EN\$binaryDesktoplinkMSI /qn" -Wait -Passthru
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\IXOS\IXOS_ARCHIVE\Profile\Default\CWin\ArchiveLink\Archive-0" /v "ADMServerName" /t REG_SZ /d "fctip1u0v.crb.apmoller.net" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\IXOS\IXOS_ARCHIVE\Profile\Default\CWin\ArchiveLink\Archive-0" /v "ADMServerName" /t REG_SZ /d "fctip1u0v.crb.apmoller.net" /f

###SAP GUI
Write-Host "installing SAP GUI  ..."
Start-Process -FilePath "$OutputPath\SAP_GUI\SAP_770\SAPGUI_SAP_7.70_R1_EN\SAP_GUI_Frontend_7.70_R1_EN\Setup\NwSapSetup.exe" -ArgumentList '/Product="SAPGUI" /Silent /NoDlg' -Wait
Start-Process -FilePath "$OutputPath\SAP_GUI\SAP_770\SAPGUI_SAP_7.70_R1_EN\SAP_GUI_Frontend_7.70_R1_EN\Setup\NwSapSetup.exe" -ArgumentList '/Product="NWBC770" /Silent /NoDlg' -Wait
Start-Process -FilePath "$OutputPath\SAP_GUI\SAP_770\SAPGUI_SAP_7.70_R1_EN\SAP_GUI_Frontend_7.70_R1_EN\Setup\NwSapSetup.exe" -ArgumentList '/Product="SAPBI" /Silent /NoDlg' -Wait
Start-Sleep -s 10
Start-Process -FilePath "$OutputPath\SAP_GUI\SAP_770\SAPGUI_SAP_7.70_R1_EN\gui770_02_1-70004692.exe" -ArgumentList '/update /silent' -Wait
Copy-Item -Path "$OutputPath\SAP_GUI\SAP_770\SAPGUI_SAP_7.70_R1_EN\NWBC.vbs" -Destination "C:\Program Files\SAP\NWBC770\"
Is-ProcessRunning -ProcName "NwSapSetup"

##FACT
Write-Host "FACT ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\SAP_GUI\SAP_770\FACT_SAP_7.70_R1_EN\$binaryFACTMSI /qn" -Wait -Passthru



#AFO SAP Component
Write-Host "installing SAP AFO..."
Write-Host "installing SAP AFO vcredist..."
Start-Process -FilePath "$OutputPath\SAP_GUI\SAP_770\AFOSAP__SAP_7.70_R1_EN\$binarySAPAFORedist" -ArgumentList '/q /norestart' -Wait
Write-Host "installing SAP AFO For Office..."
Start-Process -FilePath "$OutputPath\SAP_GUI\SAP_770\AFOSAP__SAP_7.70_R1_EN\$binarySAPAFO" -ArgumentList '/Silent /NoDlg' -Wait
#Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\SAP_GUI\SAP_770\AFOSAP__SAP_7.70_R1_EN\$binarySAPAOTools /qn" -Wait -Passthru
Copy-Item -Path "$OutputPath\SAP_GUI\SAP_770\AFOSAP__SAP_7.70_R1_EN\$binarySAPAFORoamingConfig" -Destination "C:\Program Files\SAP BusinessObjects"
Copy-Item -Path "$OutputPath\SAP_GUI\SAP_770\AFOSAP__SAP_7.70_R1_EN\$binarySAPAFOVBS" -Destination "C:\Program Files\SAP BusinessObjects"

Write-Host "SAP and Its Component Installed Successfully"

##Setting Up Apache-Jmeter-5.4.3
##Setting Up Apache-Jmeter-5.4.3
Write-Host "downloading Apache-Jmeter-5.4.3....."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryApacheJmeter$storageAccountSas", "$OutputPath\$binaryApacheJmeter")
Write-Host "downloading Apache Jar Files"
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryApacheJar$storageAccountSas", "$OutputPath\$binaryApacheJar")
Write-Host "extracting Apache-Jmeter-5.4.3..."
Expand-Archive -LiteralPath "$OutputPath\$binaryApacheJmeter" -DestinationPath "$OutputPath\apache-jmeter-5.4.3" -Force
Write-Host "Apache-Jmeter-5.4.3..."
New-Item -ItemType Directory -Path "C:\Program Files (x86)\apache-jmeter-5.4.3" -Force -Confirm:$false
Copy-Item "$OutputPath\apache-jmeter-5.4.3" -Recurse -destination "C:\Program Files (x86)\" -Force -Confirm:$false
Copy-Item -Path "$OutputPath\$binaryApacheJar" -Destination "C:\Program Files (x86)\apache-jmeter-5.4.3\apache-jmeter-5.4.3\lib"
Copy-Item -Path "$OutputPath\$binaryApacheJar" -Destination "C:\Program Files (x86)\apache-jmeter-5.4.3\apache-jmeter-5.4.3\lib\ext"

### Adobe Reader
Write-Host "downloading Adobe Reader ..."
##Extracting Adobe Reader
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryAdobe$storageAccountSas", "$OutputPath\$binaryAdobe")
Write-Host "extracting Adobe Reader ..."
Expand-Archive -LiteralPath "$OutputPath\$binaryAdobe" -DestinationPath "$OutputPath\Adobe_Reader" -Force
Write-Host "installing Adobe Reader ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\Adobe_Reader\Adobe\$binaryAdobeMSI /quiet /passive /norestart" -Wait
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /p $OutputPath\Adobe_Reader\Adobe\$binaryAdobeMSP REINSTALLMODE=omus REINSTALL=ALL /quiet /passive /norestart" -Wait
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bUpdater" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bUpdater" /t REG_DWORD /d 0 /f

### Asian Font for Acrobat Reader
Write-Host "downloading Asian Font for Acrobat Reader..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryAsianfont$storageAccountSas", "$OutputPath\$binaryAsianfont")
Write-Host "installing Asian Font for Acrobat Reader ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\$binaryAsianfont /q /n"

### Brand Central
Write-Host "downloading Brand Central ..."
##Extracting Brand Central
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryBrandCentral$storageAccountSas", "$OutputPath\$binaryBrandCentral")
Write-Host "extracting Brand Central ..."
Expand-Archive -LiteralPath "$OutputPath\$binaryBrandCentral" -DestinationPath "$OutputPath\Brand_Central" -Force
Write-Host "installing Brand Central ..."
Start-Process -FilePath  "$OutputPath\Brand_Central\BrandCentral\$binaryBrandCentralSetup" -ArgumentList " /ALLUSERS=1 /S /D=""C:\Program Files\Frontify""" -PassThru -Wait
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "electron.app.Frontify" /t REG_SZ /d "C:\Program Files\Frontify\Frontify.exe --applicationName=BrandCentral --domain=brandcentral.maersk.com --autoUpdateEnabled=false --autostartApp=False" /f
Copy-Item -Path "$OutputPath\Brand_Central\BrandCentral\Brand Central App.lnk" -Destination "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\"

###Install Tabular Editor
Write-Host "Creating AppVLauncher_Scripts Folder"
$path = "C:\Windows\AppVLauncher_Scripts"
If(!(Test-Path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}
Write-Host "downloading Tabular Editor ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryTabularEditor$storageAccountSas", "$OutputPath\$binaryTabularEditor")
Copy-Item -Path "$OutputPath\$binaryTabularEditor" -Destination "C:\Windows\AppVLauncher_Scripts\TabularEditor.msi" -Force -Confirm:$false
Start-Sleep -s 300
Write-Host "installing  Tabular Editor ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i C:\Windows\AppVLauncher_Scripts\TabularEditor.msi /qn ALLUSERS=1" -Wait -PassThru

### Delinea Protocol Handler 
Write-Host "downloading Delinea Protocol Handler..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryDelineaPH$storageAccountSas", "$OutputPath\$binaryDelineaPH")
Write-Host "installing Azure Information Protect ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList "/i $OutputPath\$binaryDelineaPH /qn"

### Delinea Connection Manager
Write-Host "downloading Delinea Connection Manager MSI ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryDelineaCMMSI$storageAccountSas", "$OutputPath\$binaryDelineaCMMSI")
Write-Host "downloading Delinea Connection Manager Config..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binaryDelineaCMCONFIG$storageAccountSas", "$OutputPath\$binaryDelineaCMCONFIG")
Write-Host "installing Delinea Connection Manager..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\$binaryDelineaCMMSI /qn" -Wait
Start-Sleep -Seconds 240
Copy-Item -Path "$OutputPath\$binaryDelineaCMCONFIG" -Destination "C:\Program Files\Delinea\Delinea Connection Manager\" -Force -Confirm:$false


### MSSQL DB For Winsad
Write-Host "downloading MSSQL DB For Winsad ..."
(New-Object System.Net.WebClient).DownloadFile("$uri/$binarymsoledbsql$storageAccountSas", "$OutputPath\$binarymsoledbsql")
Write-Host "installing MSSQL DB For Winsad ..."
Start-Process -FilePath 'c:\Windows\system32\msiexec.exe' -ArgumentList " /i $OutputPath\$binarymsoledbsql /qn IACCEPTMSOLEDBSQLLICENSETERMS=YES" -Wait -Passthru
