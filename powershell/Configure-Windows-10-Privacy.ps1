Function Configure-Windows-10-Privacy {
    Param ([switch]$Verbose)

    if ($Verbose) {
        $OldVerbosePref = $VerbosePreference
        $VerbosePreference = "Continue"
    }

    $arch = $ENV:PROCESSOR_ARCHITECTURE

    Write-Host; Write-Host "[+] Attempting to Disable Services"

    $services = @(
        "AJRouter"
        "ALG"
        "AppReadiness"
        "Browser"
        "BthHFSrv"
        "CscService"
        "DPS"
        "DevQueryBroker"
        "DiagTrack"
        "DoSvc"
        "DusmSvc"
        "EFS"
        "FDResPub"
        "FrameServer"
        "GraphicsPerfSvc"
        "HomeGroupListener"
        "HomeGroupProvider"
        "InstallService"
        "LicenseManager"
        "MSiSCSI"
        "MapsBroker"
        "NcbService"
        "NcdAutoSetup"
        "Netlogon"
        "PhoneSvc"
        "PrintNotify"
        "QWAVE"
        "RasAuto"
        "Razer Game Scanner Service"
        "RemoteAccess"
        "RemoteRegistry"
        "RetailDemo"
        "RmSvc"
        "RpcLocator"
        "RzSurroundVADStreamingService"
        "SCPolicySvc"
        "SCardSvr"
        "SDRSVC"
        "SSDPSRV"
        "ScDeviceEnum"
        "SensorDataService"
        "SensorService"
        "SensrSvc"
        "SessionEnv"
        "SharedAccess"
        "ShellHWDetection"
        "SmsRouter"
        "Spooler"
        "StorSvc"
        "SysMain"
        "TabletInputService"
        "TapiSrv"
        "TermService"
        "TokenBroker"
        "TrkWks"
        "UmRdpService"
        "WFDSConMgrSvc"
        "WMPNetworkSvc"
        "WPDBusEnum"
        "WSearch"
        "WalletService"
        "WarpJITSvc"
        "WbioSrvc"
        "WdiServiceHost"
        "WdiSystemHost"
        "WebClient"
        "WerSvc"
        "WinRM"
        "WlanSvc"
        "WpnService"
        "WwanSvc"
        "XblAuthManager"
        "XblGameSave"
        "XboxGipSvc"
        "XboxNetApiSvc"
        "bthserv"
        "defragsvc"
        "diagnosticshub.standardcollector.service"
        "dmwappushservice"
        "fdPHost"
        "fhsvc"
        "icssvc"
        "iphlpsvc"
        "irmon"
        "lfsvc"
        "pla"
        "upnphost"
        "wcncsvc"
        "wercplsupport"
        "wisvc"
        "wscsvc"
        "xbgm"
        "xboxgip"
    )
    
    foreach ($service in $services) {
        $exists = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($exists) {
            if ($exists.StartType -ne "Disabled") {
                Set-Service -Name $service -StartupType Disabled -ErrorVariable e -ErrorAction SilentlyContinue
                if (!$e) {
                    Write-Verbose -Message "[+] Service ($service) Disabled"
                } else {
                    Write-Verbose -Message "[ ] Service ($service) Not Disabled"
                }
            } else { 
                Write-Verbose -Message "[-] Service ($service) Already Disabled"
            }
        } else {
            Write-Warning -Message "[ ] Service ($service) Does Not Exist"
        }
    }

    # These services must be disabled through Registry
    $services = @(
        "CDPSvc"
        "CDPUserSvc"
        "CDPUserSvc_*"
        "DevicesFlowUserSvc_*"
        "EntAppSvc"
        "MessagingService_*"
        "OneSyncSvc"
        "OneSyncSvc_*"
        "PimIndexMaintenanceSvc"
        "PimIndexMaintenanceSvc_*"
        "PrintWorkflowUserSvc_*"
        "UnistoreSvc"
        "UnistoreSvc_*"
        "UserDataSvc"
        "UserDataSvc_*"
        "WinHttpAutoProxySvc"
        "WpnUserService"
        "WpnUserService_*"
    )

    foreach ($service in $services) {
        $exists = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($exists) {
            $start = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" -Name Start
            if ($start -ne "4") {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" -Name Start -Value 4 -ErrorVariable e -ErrorAction SilentlyContinue
                if (!$e) {
                    Write-Verbose -Message "[+] Service ($service) Disabled"
                } else {
                    Write-Verbose -Message "[ ] Service ($service) Not Disabled"
                }
            } else {
                Write-Verbose -Message "[-] Service ($service) Already Disabled"
            }
        } else {
            Write-Warning -Message "[ ] Service ($service) Does Not Exist"
        }
    }

    Write-Host; Write-Host "[+] Attempting to Disable Superfetch"
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnableSuperfetch -Value 0 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Delete Windows 10 Keylogger"
    Remove-Item -Path "C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -Force -ErrorVariable e -ErrorAction SilentlyContinue
    if ($e) {
        Write-Verbose "[x] File Already Deleted: C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    } else {
        Write-Verbose "[-] File Deleted: C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    }

    Write-Host; Write-Host "[+] Attempting to Prevent Windows 10 from repairing itself"
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\" -Name Servicing -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" -Name LocalSourcePath -Value 0.0.0.0 -PropertyType ExpandString -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" -Name UseWindowsUpdate -Value 2 -PropertyType DWORD -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\" -Name Servicing -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\" -Name LocalSourcePath -Value 0.0.0.0 -PropertyType ExpandString -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\" -Name UseWindowsUpdate -Value 2 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Remove Telemetry & Data Collection"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name PreventDeviceMetadataFromNetwork -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name DontOfferThroughWUAU -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name CEIPEnable -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name AITEnable -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name DisableUAR -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" -Name Start -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" -Name Start -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" -Name Enable -Value 0 -PropertyType DWORD -Force | Out-Null

#    Write-Host; Write-Host "[+] Windows 10 Update Delivery"
#    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name DODownloadMode -Value 0 -PropertyType DWORD -Force | Out-Null

#    Write-Host; Write-Host "[+] Attempting to modify Windows 10 Update Notification"
#    $update = Get-Service wuauserv
#    if ($update.StartType -ne "Disabled") {
#        $update | Stop-Service
#    }
#    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AutoInstallMinorUpdates -Value 0 -PropertyType DWORD -Force | Out-Null
#    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Value 2 -PropertyType DWORD -Force | Out-Null
#    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 0 -PropertyType DWORD -Force | Out-Null
#    if ($update.StartType -ne "Disabled") {
#        $update | Start-Service
#    }

    Write-Host; Write-Host "[+] Attempting to Disable MAPS"
    if ($arch -eq "x86") {
        SetACL.exe -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
        SetACL.exe -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
    } else {
        SetACLx64.exe -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
        SetACLx64.exe -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name SpyNetReporting -Value 0 -PropertyType DWORD -Force -ErrorVariable e -ErrorAction SilentlyContinue | Out-Null
    if ($e) {
        Write-Warning -Message "[!] Insufficient permissions to modify HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name SubmitSamplesConsent -Value 0 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Disable Administrative Shares"
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareWks -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareServer -Value 0 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Disable Cortana"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Value 0 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Disable MRU lists"
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackDocs -Value 0 -PropertyType DWORD -Force | Out-Null

#    Write-Host; Write-Host "[+] Attempting to Disable Windows Defender"
#    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | Out-Null

#    Write-Host; Write-Host "[+] Attempting to Remove Retail Demo"
#    Get-Item -Path "C:\ProgramData\Microsoft\Windows\RetailDemo" -ErrorVariable e -ErrorAction SilentlyContinue
#    if (!$e) {
#        takeown.exe -f "C:\ProgramData\Microsoft\Windows\RetailDemo" /A /R /D y
#        icacls.exe "C:\ProgramData\Microsoft\Windows\RetailDemo" /grant Administrators:F /T
#        Remove-Item -Path "C:\ProgramData\Microsoft\Windows\RetailDemo" -Recurse -Force
#        Write-Verbose "[-] Directory Deleted: C:\ProgramData\Microsoft\Windows\RetailDemo"
#    } else {
#        Write-Verbose "[x] Directory Already Deleted: C:\ProgramData\Microsoft\Windows\RetailDemo"
#    }

#    Get-Item -Path "C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\RetailDemo" -ErrorVariable e -ErrorAction SilentlyContinue
#    if (!$e) {
#        takeown.exe -f "C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\RetailDemo" /A /R /D y
#        icacls.exe "C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\RetailDemo" /grant Administrators:F /T
#        Remove-Item -Path "C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\RetailDemo" -Recurse -Force
#        Write-Verbose "[-] Directory Deleted: C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\RetailDemo"
#    } else {
#        Write-Verbose "[x] Directory Already Deleted: C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\RetailDemo"
#    }

    Write-Host; Write-Host "[+] Attempting to Disable LNK files"
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoRecentDocsHistory -Value 1 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Tweak Scheduled Tasks"
    $tasks = @(
    @{Path="\Microsoft\Windows\Active Directory Rights Management Services Client\"; Name="AD RMS Rights Policy Template Management (Automated)"}
    @{Path="\Microsoft\Windows\Active Directory Rights Management Services Client\"; Name="AD RMS Rights Policy Template Management (Manual)"}
    @{Path="\Microsoft\Windows\AppID\"; Name="SmartScreenSpecific"}
    @{Path="\Microsoft\Windows\Application Experience\"; Name="Microsoft Compatibility Appraiser"}
    @{Path="\Microsoft\Windows\Application Experience\"; Name="ProgramDataUpdater"}
    @{Path="\Microsoft\Windows\Application Experience\"; Name="StartupAppTask"}
    @{Path="\Microsoft\Windows\Autochk\"; Name="Proxy"}
    @{Path="\Microsoft\Windows\Bluetooth\"; Name="UninstallDeviceTask"}
    @{Path="\Microsoft\Windows\Chkdsk\"; Name="ProactiveScan"}
    @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="Consolidator"}
    @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="KernelCeipTask"}
    @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="UsbCeip"}
    @{Path="\Microsoft\Windows\Defrag\"; Name="ScheduledDefrag"}
    @{Path="\Microsoft\Windows\DiskCleanup\"; Name="SilentCleanup"}
    @{Path="\Microsoft\Windows\DiskDiagnostic\"; Name="Microsoft-Windows-DiskDiagnosticDataCollector"}
    @{Path="\Microsoft\Windows\DiskFootprint\"; Name="Diagnostics"}
    @{Path="\Microsoft\Windows\FileHistory\"; Name="File History (maintenance mode)"}
    @{Path="\Microsoft\Windows\Maintenance\"; Name="WinSAT"}
    @{Path="\Microsoft\Windows\Maps\"; Name="MapsToastTask"}
    @{Path="\Microsoft\Windows\Maps\"; Name="MapsUpdateTask"}
    @{Path="\Microsoft\Windows\Mobile Broadband Accounts\"; Name="MNO Metadata Parser"}
    @{Path="\Microsoft\Windows\Multimedia\"; Name="SystemSoundsService"}
    @{Path="\Microsoft\Windows\NetTrace\"; Name="GatherNetworkInfo"}
    @{Path="\Microsoft\Windows\NlaSvc\"; Name="WiFiTask"}
    @{Path="\Microsoft\Windows\Offline Files\"; Name="Background Synchronization"}
    @{Path="\Microsoft\Windows\Offline Files\"; Name="Logon Synchronization"}
    @{Path="\Microsoft\Windows\PI\"; Name="Sqm-Tasks"}
    @{Path="\Microsoft\Windows\Power Efficiency Diagnostics\"; Name="AnalyzeSystem"}
    @{Path="\Microsoft\Windows\Ras\"; Name="MobilityManager"}
    @{Path="\Microsoft\Windows\RemoteAssistance\"; Name="RemoteAssistanceTask"}
    @{Path="\Microsoft\Windows\RetailDemo\"; Name="CleanupOfflineContent"}
    @{Path="\Microsoft\Windows\Time Synchronization\"; Name="ForceSynchronizeTime"}
    @{Path="\Microsoft\Windows\Time Synchronization\"; Name="SynchronizeTime"}
    @{Path="\Microsoft\Windows\SettingSync\"; Name="BackgroundUploadTask"}
    @{Path="\Microsoft\Windows\SettingSync\"; Name="NetworkStateChangeTask"}
    @{Path="\Microsoft\Windows\Shell\"; Name="FamilySafetyMonitor"}
    @{Path="\Microsoft\Windows\Shell\"; Name="FamilySafetyMonitorToastTask"}
    @{Path="\Microsoft\Windows\Shell\"; Name="FamilySafetyRefreshTask"}
    @{Path="\Microsoft\Windows\Shell\"; Name="FamilySafetyUpload"}
    @{Path="\Microsoft\Windows\Shell\"; Name="IndexerAutomaticMaintenance"}
    @{Path="\Microsoft\Windows\SpacePort\"; Name="SpaceAgentTask"}
    @{Path="\Microsoft\Windows\SystemRestore\"; Name="SR"}
    @{Path="\Microsoft\Windows\User Profile Service\"; Name="HiveUploadTask"}
    @{Path="\Microsoft\Windows\WCM\"; Name="WiFiTask"}
    @{Path="\Microsoft\Windows\Windows Defender\"; Name="Windows Defender Cache Maintenance"}
    @{Path="\Microsoft\Windows\Windows Defender\"; Name="Windows Defender Cleanup"}
    @{Path="\Microsoft\Windows\Windows Defender\"; Name="Windows Defender Scheduled Scan"}
    @{Path="\Microsoft\Windows\Windows Defender\"; Name="Windows Defender Verification"}
    @{Path="\Microsoft\Windows\Windows Error Reporting\"; Name="QueueReporting"}
    @{Path="\Microsoft\Windows\WindowsUpdate\"; Name="Automatic App Update"}
    @{Path="\Microsoft\Windows\WindowsUpdate\"; Name="Scheduled Start"}
    @{Path="\Microsoft\Windows\Wininet\"; Name="CacheTask"}
    @{Path="\Microsoft\Windows\Workplace Join\"; Name="Automatic-Device-Join"}
    @{Path="\Microsoft\XblGameSave\"; Name="XblGameSaveTask"}
    @{Path="\Microsoft\XblGameSave\"; Name="XblGameSaveTaskLogon"}
    )
 
     foreach ($task in $tasks) {
        $exists = Get-ScheduledTask -TaskPath $task.Path -TaskName $task.Name -ErrorAction SilentlyContinue
        if ($exists) {
            if ($exists.State -ne "Disabled") {
                Disable-ScheduledTask -TaskPath $task.Path -TaskName $task.Name -ErrorVariable e -ErrorAction SilentlyContinue | Out-Null
                if (!$e) {
                    Write-Verbose -Message "[-] Task Disabled: $($task.Name)"
                } else {
                    Write-Verbose -Message "[ ] Task Disabled: $($task.Name)"
                }
            } else {
                Write-Verbose -Message "[-] Task Disabled: $($task.Name)"
            }
        } else {
            Write-Warning -Message "[ ] DoesNot Exist: $($task.Name)"
        }
    }

    Write-Host; Write-Host "[+] Attempting to Disable Windows Event logs"
    $logs = Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue

    $logs | % -Process {
        $log = $_
        if ($log) {
            if ($log.get_IsClassicLog()) {
                Write-Warning -Message "[ ] Cannot Disable Classic Log: $($log.LogName)"
            } else {
                try {
                    if ($log.get_IsEnabled()) {
                        $log.set_IsEnabled($false)
                        $log.SaveChanges() | Out-Null
                        Write-Verbose -Message "[-] Log Disabled: $($log.LogName)"
                    } else {
                        Write-Verbose -Message "[-] Log Disabled: $($log.LogName)"
                    }
                } catch {
                    Write-Verbose -Message "[ ] Log Disabled: $($log.LogName) ($($log.Exception.Message))"
                }
            }
        } else {
            Write-Warning -Message "[ ] DoesNotExist: $($log.LogName)"
        }
    }

#    Write-Host; Write-Host "[+] Attempting to Disable CPU Parking"
#    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name ValueMax -Value 0 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Disable IPv6"
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name DisabledComponents -Value 1 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Disable UPnP"
    New-ItemProperty -Path "HKLM:\Software\Microsoft\DirectplayNATHelp\DPNHUPnP" -Name UPnPMode -Value 2 -PropertyType DWORD -Force | Out-Null

    Write-Host; Write-Host "[+] Attempting to Disable IGMP"
    Set-NetIPv4Protocol -IGMPLevel None

    Write-Host; Write-Host "[+] Attempting to Disable BackgroundUploadTask & Metadata Refresh Scheduled Tasks"
    $tasks = @(
        "BackgroundUploadTask"
        "Metadata Refresh"
    )
    $keys = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
    foreach ($task in $tasks) {
        :outer
        foreach ($key in $keys) {
            $path = Get-ItemProperty -Path $key.PSPath -Name Path
            foreach ($subkey in $path) {
                if ($task -in $subkey.Path.Split("\")) {
                    $guid = $subkey.PSChildName
                    break outer
                }  
            }
        }
        $data = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid" -Name Triggers
        if ([Convert]::ToString($data[42], 16) -eq "c0") {
            if ($arch -eq "x86") {
                SetACL.exe -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
                SetACL.exe -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
            } else {
                SetACLx64.exe -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
                SetACLx64.exe -on "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
            }
            $data[42] = 0
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$guid" -Name Triggers -Value $data -PropertyType Binary -Force | Out-Null
        } elseif ([Convert]::ToString($data[42], 16) -eq '0') {
            Write-Verbose "[x] Scheduled task $task already modified"
        } else {
            Write-Warning -Message "[!] Failed to Modify Tasks"
        }
    }

    Write-Host; Write-Host "[+] Attempting to Block Microsoft Telemetry and Data Collection Domains in hosts File"
    $domains = @"
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 telecommand.telemetry.microsoft.com
0.0.0.0 oca.telemetry.microsoft.com
0.0.0.0 sqm.telemetry.microsoft.com
0.0.0.0 watson.telemetry.microsoft.com
0.0.0.0 redir.metaservices.microsoft.com
0.0.0.0 choice.microsoft.com
0.0.0.0 df.telemetry.microsoft.com
0.0.0.0 reports.wes.df.telemetry.microsoft.com
0.0.0.0 wes.df.telemetry.microsoft.com
0.0.0.0 services.wes.df.telemetry.microsoft.com
0.0.0.0 sqm.df.telemetry.microsoft.com
0.0.0.0 telemetry.microsoft.com
0.0.0.0 watson.ppe.telemetry.microsoft.com
0.0.0.0 telemetry.appex.bing.net
0.0.0.0 telemetry.urs.microsoft.com
0.0.0.0 settings-sandbox.data.microsoft.com
0.0.0.0 vortex-sandbox.data.microsoft.com
0.0.0.0 survey.watson.microsoft.com
0.0.0.0 watson.live.com
0.0.0.0 watson.microsoft.com
0.0.0.0 statsfe2.ws.microsoft.com
0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com
0.0.0.0 compatexchange.cloudapp.net
0.0.0.0 cs1.wpc.v0cdn.net
0.0.0.0 a-0001.a-msedge.net
0.0.0.0 statsfe2.update.microsoft.com.akadns.net
0.0.0.0 sls.update.microsoft.com.akadns.net
0.0.0.0 fe2.update.microsoft.com.akadns.net
0.0.0.0 diagnostics.support.microsoft.com
0.0.0.0 corp.sts.microsoft.com
0.0.0.0 statsfe1.ws.microsoft.com
0.0.0.0 pre.footprintpredict.com
0.0.0.0 i1.services.social.microsoft.com
0.0.0.0 feedback.windows.com
0.0.0.0 feedback.microsoft-hohm.com
0.0.0.0 feedback.search.microsoft.com
0.0.0.0 rad.msn.com
0.0.0.0 preview.msn.com
0.0.0.0 dart.l.doubleclick.net
0.0.0.0 ads.msn.com
0.0.0.0 a.ads1.msn.com
0.0.0.0 global.msads.net.c.footprint.net
0.0.0.0 az361816.vo.msecnd.net
0.0.0.0 oca.telemetry.microsoft.com.nsatc.net
0.0.0.0 reports.wes.df.telemetry.microsoft.com
0.0.0.0 df.telemetry.microsoft.com
0.0.0.0 cs1.wpc.v0cdn.net
0.0.0.0 vortex-sandbox.data.microsoft.com
0.0.0.0 pre.footprintpredict.com
0.0.0.0 i1.services.social.microsoft.com
0.0.0.0 ssw.live.com
0.0.0.0 statsfe1.ws.microsoft.com
0.0.0.0 msnbot-65-55-108-23.search.msn.com
0.0.0.0 a23-218-212-69.deploy.static.akamaitechnologies.com
0.0.0.0 wns.windows.com
"@

    Write-Host; Write-Host "[-] Attempting to replace hosts file"
    Write-Output $domains | Out-File -FilePath C:\Windows\System32\drivers\etc\hosts

    Write-Host; Write-Host "[+] Attempting to Remove Unneccessary Firewall Rules"
    $groups = @(
        "Virtual Machine Monitoring"
        "Remote Shut-down"
        "Remote Event Monitor"
        "iSCSI Service"
        "Windows Firewall Remote Management"
        "AllJoyn Router"
        "Proximity Sharing"
        "Wireless Display"
        "DIAL protocol server"
        "TPM Virtual Smart Card Management"
        "Routing and Remote Access"
        "WLAN Service – WFD Application Services Platform Coordination Protocol (Uses UDP)"
        "Remote Assistance"
        "Remote Event Log Management"
        "WiFi Direct Network Discovery"
        "Remote Service Management"
        "Performance Logs and Alerts"
        "Windows Remote Management"
        "Windows Remote Management (Compatibility)"
        "Remote Volume Management"
        "Remote Scheduled Tasks Management"
        "Media Center Extenders"
        "Wireless Portable Devices"
        "Cast to Device functionality"
        "@{Microsoft.AccountsControl_10.0.10586.0_neutral__cw5n1h2txyewy?ms-resource://Microsoft.AccountsControl/Resources/DisplayName}"
        "@{Microsoft.Windows.CloudExperienceHost_10.0.10586.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.CloudExperienceHost/resources/appDescription}"
        "windows_ie_ac_001"
        "Work or school account"
        "Your account"
        "Windows Shell Experience"
        "Cortana"
        "Email and accounts"
        "Windows Default Lock Screen"
        "Microsoft Edge"
        "Connect"
        "SmartScreen"
        "Windows Spotlight"
        "Microsoft family features"
        "Xbox Game UI"
        "Contact Support"
        "DiagTrack"
        "Get Help"
        "Remote Administration"
        "Remote Desktop"
        "Remote Shutdown"
        "SNMP Trap"
        "Wi-Fi Direct Network Discovery"
        "Windows Collaboration Computer Name Registration Service"
        "Windows Peer to Peer Collaboration Foundation"
        "WLAN Service - WFD Application Services Platform Coordination Protocol (Uses UDP)"
        "WLAN Service - WFD Services Kernel Mode Driver Rules"
        "Captive Portal Flow"
        "Microsoft Content"
        "Take a Test"
        "Paint 3D"
    )

    foreach ($group in $groups) {
        $exists = Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue
        if ($exists) {
            Remove-NetFirewallRule -DisplayGroup $group -ErrorVariable e -ErrorAction SilentlyContinue
            if ($e) {
                Write-Warning -Message "[!] Failed to Remove Firewall Rules in Group: $group"
            } else {
                Write-Verbose "[-] Successfully Removed Firewall Rules in Group: $group"
            }
        } else {
            Write-Verbose "[x] Firewall Group Does Not Exist: $group"
        }
    }

    Write-Host; Write-Host "[+] Attempting to Create Firewall Rule to Block MarkMonitor Inc"

    Get-NetFirewallRule -Name "Block MarkMonitor Inc" -ErrorVariable e -ErrorAction SilentlyContinue | Out-Null
    if ($e) {
        Remove-Variable e
        New-NetFirewallRule -Name "Block MarkMonitor Inc" -DisplayName "Block MarkMonitor Inc" -Group "Enable Privacy" -Direction Outbound -Action Block -Profile Any -RemoteAddress @("111.221.29.0/24", "111.221.124.0/24") -EdgeTraversalPolicy Block -Enabled True -ErrorVariable e -ErrorAction SilentlyContinue | Out-Null
        if ($e) {
            Write-Warning -Message "[!] Failed to Create Firewall Rule to Block MarkMonitor Inc"
        } else {
            Write-Verbose "[-] Created Firewall Rule to Block MarkMonitor Inc"
        }
    } else {
        Set-NetFirewallRule -Name "Block MarkMonitor Inc" -RemoteAddress @("111.221.124.0/24", "111.221.29.0/24")
        Write-Verbose "[-] Updated Firewall Rule to Block MarkMonitor Inc"
    }

    Write-Host; Write-Host "[+] Attempting to Remove Windows 10 Bloatware"
    $apps = @(
        "Microsoft.3DBuilder"
        "Microsoft.Appconnector"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingWeather"
        "Microsoft.DesktopAppInstaller"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MicrosoftStickyNotes"
        "Microsoft.Office.OneNote"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Reader"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Windows.Photos"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCalculator"
        "Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.WindowsStore"
        "Microsoft.XboxApp"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        #"Microsoft.Windows.CloudExperienceHost"
        #"Microsoft.Windows.ShellExperienceHost"
        #"windows.immersivecontrolpanel"
        #"Microsoft.Windows.Cortana"
        #"Microsoft.AccountsControl"
        #"Microsoft.LockApp"
        #"Microsoft.MicrosoftEdge"
        #"Microsoft.PPIProjection"
        #"Microsoft.Windows.Apprep.ChxApp"
        #"Microsoft.Windows.ContentDeliveryManager"
        #"Microsoft.Windows.ParentalControls"
        #"Microsoft.Windows.SecondaryTileExperience"
        #"Microsoft.XboxGameCallableUI"
        #"Windows.ContactSupport"
        #"Windows.MiracastView"
        #"Windows.PrintDialog"
        #"microsoft.windowscommunicationsapps"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.Wallet"
        "Microsoft.Advertising.Xaml"
        "Microsoft.Windows.SecHealthUI"
        "Microsoft.Windows.OOBENetworkCaptivePortal"
        "Microsoft.Windows.OOBENetwoworkConnectionFlow"
        "Microsoft.Windows.Apprep.ChxApp"
        "Microsoft.Print3D"
        "Microsoft.Services.Store.Engagement"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.GetHelp"
        "Microsoft.PeopleExperienceHost"
    )
    foreach ($app in $apps) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppXProvisionedPackage -Online | Where-Object DisplayName -EQ $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue        
    }

    Write-Host; Write-Host "[+] Clearing All Event Logs"
    wevtutil.exe el | % { Write-Verbose "[-] Clearing Event Log: $_"; wevtutil.exe cl $_ }

Write-Host "Reboot system for changes to take effect"
    
$VerbosePreference = $OldVerbosePref
Remove-Item Function:\Configure-Windows-10-Privacy
}
