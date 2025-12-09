# Kaspa RPC Client Firewall Configuration Script
# Run this script as Administrator

Write-Host "=== Kaspa RPC Client Firewall Configuration ===" -ForegroundColor Cyan
Write-Host ""

# Get the path to the executable
$exePath = "C:\Users\max\p2pComm\target\release\kaspa-testnet-test.exe"

if (Test-Path $exePath) {
    Write-Host "[OK] Found executable: $exePath" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Executable not found at: $exePath" -ForegroundColor Yellow
    Write-Host "The firewall rule will still be created, but may not work until you build the project." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Creating firewall rules..." -ForegroundColor Cyan

# Rule 1: Allow the Kaspa test application (outbound)
Write-Host "  1. Allowing kaspa-testnet-test.exe outbound connections..." -ForegroundColor White
try {
    New-NetFirewallRule -DisplayName "Kaspa Testnet Test - Outbound" `
        -Description "Allow Kaspa testnet test application to connect to Kaspa RPC endpoints" `
        -Direction Outbound `
        -Program $exePath `
        -Action Allow `
        -Protocol TCP `
        -Enabled True `
        -Profile Any `
        -ErrorAction Stop | Out-Null
    Write-Host "     [OK] Created outbound rule for application" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -like "*already exists*") {
        Write-Host "     [SKIP] Rule already exists" -ForegroundColor Yellow
    } else {
        Write-Host "     [ERROR] Failed to create rule: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Rule 2: Allow WebSocket connections on port 443 (HTTPS/WSS)
Write-Host "  2. Allowing outbound WebSocket connections (port 443)..." -ForegroundColor White
try {
    New-NetFirewallRule -DisplayName "Kaspa RPC - WebSocket Port 443" `
        -Description "Allow outbound WebSocket connections to Kaspa RPC endpoints on port 443" `
        -Direction Outbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort Any `
        -RemotePort 443 `
        -Enabled True `
        -Profile Any `
        -ErrorAction Stop | Out-Null
    Write-Host "     [OK] Created outbound rule for port 443" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -like "*already exists*") {
        Write-Host "     [SKIP] Rule already exists" -ForegroundColor Yellow
    } else {
        Write-Host "     [ERROR] Failed to create rule: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Rule 3: Allow WebSocket connections on port 17210 (Kaspa testnet Borsh)
Write-Host "  3. Allowing outbound connections on port 17210 (testnet Borsh)..." -ForegroundColor White
try {
    New-NetFirewallRule -DisplayName "Kaspa RPC - Testnet Borsh Port 17210" `
        -Description "Allow outbound connections to Kaspa testnet RPC endpoints on port 17210" `
        -Direction Outbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort Any `
        -RemotePort 17210 `
        -Enabled True `
        -Profile Any `
        -ErrorAction Stop | Out-Null
    Write-Host "     [OK] Created outbound rule for port 17210" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -like "*already exists*") {
        Write-Host "     [SKIP] Rule already exists" -ForegroundColor Yellow
    } else {
        Write-Host "     [ERROR] Failed to create rule: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Rule 4: Allow WebSocket connections on port 18210 (Kaspa testnet JSON)
Write-Host "  4. Allowing outbound connections on port 18210 (testnet JSON)..." -ForegroundColor White
try {
    New-NetFirewallRule -DisplayName "Kaspa RPC - Testnet JSON Port 18210" `
        -Description "Allow outbound connections to Kaspa testnet RPC endpoints on port 18210" `
        -Direction Outbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort Any `
        -RemotePort 18210 `
        -Enabled True `
        -Profile Any `
        -ErrorAction Stop | Out-Null
    Write-Host "     [OK] Created outbound rule for port 18210" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -like "*already exists*") {
        Write-Host "     [SKIP] Rule already exists" -ForegroundColor Yellow
    } else {
        Write-Host "     [ERROR] Failed to create rule: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Firewall Configuration Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Created firewall rules:" -ForegroundColor White
Write-Host "  - Kaspa Testnet Test - Outbound (application-specific)" -ForegroundColor Gray
Write-Host "  - Kaspa RPC - WebSocket Port 443 (wss://)" -ForegroundColor Gray
Write-Host "  - Kaspa RPC - Testnet Borsh Port 17210" -ForegroundColor Gray
Write-Host "  - Kaspa RPC - Testnet JSON Port 18210" -ForegroundColor Gray
Write-Host ""
Write-Host "You can now run the Kaspa testnet tests." -ForegroundColor Green
Write-Host ""
Write-Host "To verify the rules were created, run:" -ForegroundColor Yellow
Write-Host "  Get-NetFirewallRule -DisplayName '*Kaspa*' | Format-Table DisplayName, Enabled, Direction" -ForegroundColor Gray
Write-Host ""
Write-Host "To remove these rules later, run:" -ForegroundColor Yellow
Write-Host "  Remove-NetFirewallRule -DisplayName '*Kaspa*'" -ForegroundColor Gray
Write-Host ""
