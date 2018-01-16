Function Disable-All-WinEvents {

    Begin {
        $AllLogs = Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue
    }

    Process {

        $AllLogs | % -Process {
            if ($_) {
                if ($_.get_IsClassicLog()) {
                    Write-Warning -Message "[!] Cannot Disable Classic Log $($_.LogName)"
                } else {
                    try {
                        if ($_.get_IsEnabled()) {
                            $_.set_IsEnabled($False)
                            $_.SaveChanges() | Out-Null
                            Write-Host "[-] Successfully Disabled: $($_.LogName)"
                        } else {
                            Write-Host "[x] Already Disabled: $($_.LogName)"
                        }
                    } catch {
                        Write-Warning -Message "[!] Failed to Disable $($_.LogName) Due to Error $($_.Exception.Message)"
                    }
                }
            } else {
                Write-Warning -Message "[!] Cannot Find: $($_.LogName)"
            }
        }
    }
}
