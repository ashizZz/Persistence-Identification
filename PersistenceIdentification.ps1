# Function to check registry persistence keys
function Check-RegistryPersistence {
    $sysKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    Write-Host "`r`n[+] Checking Registry Persistence Keys:`r`n"
    ForEach ($key in $sysKeys) {
        if (Test-Path $key) {
            Write-Host "Found: $key"
            Try {
                # Check if the registry key contains any properties
                $properties = Get-ItemProperty -Path $key
                if ($properties) {
                    $properties | Format-List
                } else {
                    Write-Host "No properties found at $key"
                }
            }
            Catch {
                Write-Host "Error accessing registry path $key. Error: $_"
            }
        } else {
            Write-Host "Path does not exist: $key"
        }
    }
}

# Function to list installed services
function Check-InstalledServices {
    Write-Host "`r`n[+] Installed Services:`r`n"
    Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName | Format-List
}

# Function to check scheduled tasks for suspicious activity
function Check-ScheduledTasks {
    Write-Host "`r`n[+] Checking Scheduled Tasks:`r`n"
    $tasks = Get-ChildItem "C:\Windows\System32\Tasks" -Recurse
    ForEach ($task in $tasks) {
        Write-Host "`r`n[t] Task: $task"
        Write-Host "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ `r`n"
        Get-Content $task.FullName -ErrorAction SilentlyContinue | Select-String -Pattern '<Command>' -SimpleMatch
    }
}

# Function to check WMI subscriptions for persistence
function Check-WMISubscriptions {
    Write-Host "`r`n[+] Checking WMI Subscriptions:`r`n"
    Get-WmiObject -Namespace root\Subscription -Class __EventFilter | Format-Table -AutoSize
}

# Function to check startup folders for potential persistence entries
function Check-StartupFolders {
    Write-Host "`r`n[+] Checking Startup Folder Contents:`r`n"
    $startupPath = 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*'
    Get-ChildItem $startupPath | Where-Object { $_.Name -ne 'desktop.ini' }
}

# Function to check recently terminal services (RDP) logins
function Check-RDPTerminalLogins {
    Write-Host "`r`n[+] Checking Recently Terminal Services Logins:`r`n"
    $before = (Get-Date).AddDays(-7)  # Expanding the time range to the last 7 days for broader results
    $after = (Get-Date)
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$before; EndTime=$after} |
            Where-Object { $_.Properties[8].Value -like "*RDP*" }

        if ($events) {
            $events | Select-Object TimeCreated, @{Name="User"; Expression={$_.Properties[5].Value}}, @{Name="IP"; Expression={$_.Properties[18].Value}} | Format-Table -AutoSize
        } else {
            Write-Host "No RDP logins found in the last 7 days."
        }
    }
    catch {
        Write-Host "Error while fetching RDP login events: $_"
    }
}

# Function to check for recently written files (within the last 24 hours)
function Check-RecentlyWrittenFiles {
    Write-Host "`r`n[+] Checking Recently Written Files:`r`n"
    $recentFiles = Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
        Select-Object FullName, LastWriteTime | Format-Table -AutoSize

    ForEach ($file in $recentFiles) {
        Write-Host $file.FullName
    }
}

# Function to check NTFS alternate data streams
function Check-NTFSAlternateDataStreams {
    Write-Host "`r`n[+] Checking NTFS Alternate Data Streams:`r`n"
    $files = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue
    ForEach ($file in $files) {
        Get-Item -Path $file.FullName -Stream * |
        Where-Object { $_.Stream -ne ":$DATA" } |
        Select-Object FileName, Stream | Format-Table -AutoSize
    }
}

# Main menu loop
do {
    Write-Host "`r`n[+] Please select an option:"
    Write-Host "1. Check Registry Persistence Keys"
    Write-Host "2. List Installed Services"
    Write-Host "3. Check Scheduled Tasks"
    Write-Host "4. Check WMI Subscriptions"
    Write-Host "5. Check Startup Folders"
    Write-Host "6. Check Recently Terminal Services Logins"
    Write-Host "7. Check Recently Written Files"
    Write-Host "8. Check NTFS Alternate Data Streams"
    Write-Host "9. Exit"

    $choice = Read-Host "Enter the number of your choice"

    switch ($choice) {
        1 { Check-RegistryPersistence }
        2 { Check-InstalledServices }
        3 { Check-ScheduledTasks }
        4 { Check-WMISubscriptions }
        5 { Check-StartupFolders }
        6 { Check-RDPTerminalLogins }
        7 { Check-RecentlyWrittenFiles }
        8 { Check-NTFSAlternateDataStreams }
        9 { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid choice. Please select a valid option." }
    }
} while ($choice -ne 9)
