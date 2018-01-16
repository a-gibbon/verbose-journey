Function Disable-Unnecessary-Services {
    Param ([switch]$Verbose)

    if ($Verbose) {
        $OldVerbosePref = $VerbosePreference
        $VerbosePreference = "Continue"
    }

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
Remove-Item Function:\Disable-Unnecessary-Services
}
