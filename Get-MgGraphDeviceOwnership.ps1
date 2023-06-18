<#
.SYNOPSIS
    Script written to get devices and their ownership information from Microsoft Graph
.EXAMPLE
    ./Get-MgGraphDeviceOwnership.ps1
.NOTES
    Author: Padure Sergio
    Company: Raindrops.dev
    Last Edit: 2023-06-18
    Version 0.1 Initial functional code
#>

param (
    [Parameter(Mandatory = $false)]
    [PSObject[]]$users = @(),
    [Parameter(Mandatory = $false)]
    [Switch]$export,
    [Parameter(Mandatory = $false)]
    [String]$exportFileName = "UserDeviceOwnership_" + (Get-Date -Format "yyMMdd_HHMMss") + ".csv",
    [Parameter(Mandatory = $false)]
    [String]$exportPath = [Environment]::GetFolderPath("Desktop")
)

#Clearing the screen
Clear-Host

#Preparing the output object
$deviceOwnership = @()


if ($users.Count -eq 0) {
    Write-Output "No user has been provided, gathering data for all devices in the tenant"
    #Getting all Devices and their registered owners
    $devices = Get-MgDevice -All -Property * -ExpandProperty registeredOwners

    #For each device which has a registered owner, extract the device data and the registered owner data
    foreach ($device in $devices) {
        $DeviceOwners = $device | Select-Object -ExpandProperty 'RegisteredOwners'
        #Checking if the DeviceOwners Object is empty
        if ($DeviceOwners -ne $null) {
            foreach ($DeviceOwner in $DeviceOwners) {
                $OwnerDictionary = $DeviceOwner.AdditionalProperties
                $OwnerDisplayName = $OwnerDictionary.Item('displayName')
                $OwnerUPN = $OwnerDictionary.Item('userPrincipalName')
                $OwnerID = $deviceOwner.Id
                $deviceOwnership += [PSCustomObject]@{
                    DeviceDisplayName             = $device.DisplayName
                    DeviceId                      = $device.DeviceId
                    DeviceOSType                  = $device.OperatingSystem
                    DeviceOSVersion               = $device.OperatingSystemVersion
                    DeviceTrustLevel              = $device.TrustType
                    DeviceIsCompliant             = $device.IsCompliant
                    DeviceIsManaged               = $device.IsManaged
                    DeviceObjectId                = $device.Id
                    DeviceOwnerID                 = $OwnerID
                    DeviceOwnerDisplayName        = $OwnerDisplayName
                    DeviceOwnerUPN                = $OwnerUPN
                    ApproximateLastLogonTimestamp = $device.ApproximateLastSignInDateTime
                }
            }
        }

    }
}

else {
    #Checking that userid is present in the users object
    Write-Output "List of users has been provided, gathering data for all devices owned by the provided users"
    foreach ($user in $users) {
        $devices = Get-MgUserOwnedDevice -UserId $user.Id -Property *
        foreach ($device in $devices) {
            $DeviceHashTable = $device.AdditionalProperties
            $deviceOwnership += [PSCustomObject]@{
                DeviceId                      = $DeviceHashTable.Item('deviceId')
                DeviceOSType                  = $DeviceHashTable.Item('operatingSystem')
                DeviceOSVersion               = $DeviceHashTable.Item('operatingSystemVersion') 
                DeviceTrustLevel              = $DeviceHashTable.Item('trustType')
                DeviceDisplayName             = $DeviceHashTable.Item('displayName')
                DeviceIsCompliant             = $DeviceHashTable.Item('isCompliant')
                DeviceIsManaged               = $DeviceHashTable.Item('isManaged')
                DeviceObjectId                = $device.Id
                DeviceOwnerUPN                = $user.UserPrincipalName
                DeviceOwnerID                 = $user.Id
                DeviceOwnerDisplayName        = $user.DisplayName
                ApproximateLastLogonTimestamp = $DeviceHashTable.Item('approximateLastSignInDateTime')
            }
        }
    }

}

$deviceOwnership

if ($export) {
    $exportFile = Join-Path -Path $exportPath -ChildPath $exportFileName
    $deviceOwnership | Export-Csv -Path $exportFile -NoTypeInformation
    Write-Output "Data has been exported to $exportFile"
}