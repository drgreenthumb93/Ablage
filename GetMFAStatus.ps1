Function Get-AzureMFAStatus {
    <#
    .Synopsis
        This will get the Multi-factor authentication status of your users and determine which of them or not are admins.
        For updated help and examples refer to -Online version.
      
     
    .DESCRIPTION
        This will get the Multi-factor authentication status of your users and determine which of them or not are admins.
        For updated help and examples refer to -Online version.
     
     
    .NOTES  
        Name: Get-AzureMFAStatus
        Author: theSysadminChannel
        Version: 1.0
        DateCreated: 2019-Feb-08
     
     
    .LINK
        https://thesysadminchannel.com/get-mfa-status-for-azure-office365-users-using-powershell -
    #>
     
        [CmdletBinding(DefaultParameterSetName="Default")]
        param(
            [Parameter(
                Position  = 0,
                Mandatory = $false,
                ValueFromPipeline =$true,
                ValueFromPipelineByPropertyName=$true,
                ParameterSetName = "UserPrincipalName"
            )]
            [string[]]   $UserPrincipalName,
     
     
            [Parameter(
                Mandatory         = $false,
                ValueFromPipeline = $false,
                ParameterSetName  = "ResultList"
            )]
            [int]        $MaxResults = 2000,
     
     
            [Parameter(
                Mandatory         = $false,
                ValueFromPipeline = $false,
                ParameterSetName  = "ResultList"
            )]
            [bool]       $isLicensed = $true,
     
     
            [Parameter(
                Mandatory         = $false,
                ValueFromPipeline = $false
            )]
            [switch]     $SkipAdminCheck
     
     
        )
     
     
        BEGIN {
            if (-not $SkipAdminCheck) {
                $AdminUsers = Get-MsolRole -ErrorAction Stop | foreach {Get-MsolRoleMember -RoleObjectId $_.ObjectID} | Where-Object {$null -ne $_.EmailAddress} | Select EmailAddress -Unique | Sort-Object EmailAddress
            }
        }
     
        PROCESS {
            if ($PSBoundParameters.ContainsKey("UserPrincipalName")) {
                foreach ($MsolUser in $UserPrincipalName) {
                    try {
                        $User = Get-MsolUser -UserPrincipalName $MsolUser -ErrorAction Stop
     
                        if ($SkipAdminCheck) {
                            $isAdmin = "-"
                          } else {
                            if ($AdminUsers -match $User.UserPrincipalName) {
                                $isAdmin = $true
                              } else {
                                $isAdmin = $false
                            }
                        }
     
                        if ($User.StrongAuthenticationMethods) {
                            $MFAEnabled = $true
                          } else {
                            $MFAEnabled = $false
                        }
     
     
                        [PSCustomObject]@{
                            DisplayName       = $User.DisplayName
                            UserPrincipalName = $User.UserPrincipalName
                            isAdmin           = $isAdmin
                            MFAEnabled        = $MFAEnabled
                        }
     
                    } catch {
                        [PSCustomObject]@{
                            DisplayName       = '_NotSynced'
                            UserPrincipalName = $User
                            isAdmin           = '-'
                            MFAEnabled        = '-'
                        }
                    } finally {
                        $null = $User
                        $null = $isAdmin
                        $null = $MFAEnabled
                    }
                }
            } else {
                $AllUsers = Get-MsolUser -MaxResults $MaxResults | Where-Object {$_.IsLicensed -eq $isLicensed}
                foreach ($User in $AllUsers) {
                    if ($SkipAdminCheck) {
                        $isAdmin = "-"
                      } else {
                        if ($AdminUsers -match $User.UserPrincipalName) {
                            $isAdmin = $true
                          } else {
                            $isAdmin = $false
                        }
                    }
     
                    if ($User.StrongAuthenticationMethods) {
                        $MFAEnabled = $true
                      } else {
                        $MFAEnabled = $false
                    }
     
     
                    [PSCustomObject]@{
                        DisplayName       = $User.DisplayName
                        UserPrincipalName = $User.UserPrincipalName
                        isAdmin           = $isAdmin
                        MFAEnabled        = $MFAEnabled
                    }
     
                    $null = $User
                    $null = $isAdmin
                    $null = $MFAEnabled
     
                }
            }
        }
     
        END {}
     
    }
