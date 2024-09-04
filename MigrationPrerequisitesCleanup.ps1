<#
    .SYNOPSIS
    This script will delete all role assignments and delete user managed identity created for migration of machines and software update configurations from Azure Automation Update Management to Azure Update Manager.

    .DESCRIPTION
    This script will do the following:
    1. Retrieve all machines onboarded to Azure Automation Update Management under this automation account from linked Log Analytics Workspace.
    2. Delete an automation variable with name AutomationAccountAzureEnvironment created for use in migration.
    3. Remove the user managed identity from the automation account
    4. Delete assigned roles to the user managed identity.
    5. Delete the user managed identity.

    The executor of the script should have Microsoft.Authorization/roleAssignments/write action such as Role Based Access Control Administrator on the scopes on which access will be revoked to user managed identity. 

    .PARAMETER AutomationAccountResourceId
        Mandatory
        Automation Account Resource Id.

    .PARAMETER AutomationAccountAzureEnvironment
        Mandatory
        Azure Cloud Environment to which Automation Account belongs.
        Accepted values are AzureCloud, AzureUSGovernment, AzureChinaCloud.
        
    .EXAMPLE
        MigrationPrerequisitesCleanup -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}" -AutomationAccountAzureEnvironment "AzureCloud"

    .OUTPUTS
        The role assignments and user managed identity deleted.
#>
param (
	
    [Parameter(Mandatory = $true)]
    [String]$AutomationAccountResourceId,
    [Parameter(Mandatory = $true)]
    [String]$AutomationAccountAzureEnvironment = "AzureCloud"
)

# Telemetry level.
$Debug = "Debug"
$Verbose = "Verbose"
$Informational = "Informational"
$Warning = "Warning"
$ErrorLvl = "Error"

$Succeeded = "Succeeded"
$Failed = "Failed"

# API versions.
$AutomationApiVersion = "2023-11-01"; # Azure Automation: https://learn.microsoft.com/rest/api/automation/automation-account
$SoftwareUpdateConfigurationApiVersion = "2023-11-01"; # Azure Software Update Configurations: https://learn.microsoft.com/rest/api/automation/softwareupdateconfigurations
$UserManagedIdentityApiVersion = "2023-01-31"; # Managed Identities: https://learn.microsoft.com/rest/api/managedidentity/user-assigned-identities
$AzureRoleAssignmentsApiVersion = "2022-04-01"; # Azure Role Assignments: https://learn.microsoft.com/rest/api/authorization/role-assignments
$AutomationVariableApiVersion = "2023-11-01"; # Azure Automation Variables: https://learn.microsoft.com/rest/api/automation/variable

# HTTP methods.
$GET = "GET"
$PATCH = "PATCH"
$PUT = "PUT"
$POST = "POST"
$DELETE = "DELETE"

# ARM endpoints.
$LinkedWorkspacePath = "{0}/linkedWorkspace"
$SoftwareUpdateConfigurationsPath = "{0}/softwareUpdateConfigurations?`$skip={1}"
$UserManagedIdentityPath = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{2}"
$AzureListRoleAssignmentsPath = "{0}/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('{1}')"
$AutomationVariablePath = "{0}/variables/AutomationAccountAzureEnvironment"

# Role Definition IDs.
$AzureConnectedMachineOnboardingRole = "b64e21ea-ac4e-4cdf-9dc9-5b892992bee7"
$VirtualMachineContributorRole = "9980e02c-c2be-4d73-94e8-173b1dc7cf3c"
$LogAnalyticsContributorRole = "92aaf0da-9dab-42b6-94a3-d43ce8d16293"
$LogAnalyticsReaderRole = "73c42c96-874c-492b-b04d-ab87d138a893"
$AutomationOperatorRole = "d3881f73-407a-4167-8283-e981cbba0404"
$ScheduledPatchingContributorRole = "cd08ab90-6b14-449c-ad9a-8f8e549482c6"
$ContributorRole = "b24988ac-6180-42a0-ab88-20f7382dd24c"


# Validation values.
$TelemetryLevels = @($Debug, $Verbose, $Informational, $Warning, $ErrorLvl)
$HttpMethods = @($GET, $PATCH, $POST, $PUT, $DELETE)

#Max depth of payload.
$MaxDepth = 5

# Beginning of Payloads.

$RemoveMigrationUserManagedIdentityFromAutomationAccountPayload = @"
{
    "identity": {
      "type": ""
    }
}
"@

# End of Payloads.

$MachinesOnboaredToAutomationUpdateManagementQuery = 'Heartbeat | where Solutions contains "updates" | distinct Computer, ResourceId, ResourceType, OSType'
$Global:Machines = [System.Collections.ArrayList]@()
$Global:SoftwareUpdateConfigurationsResourceIDs = @{ }
$Global:AzureDynamicQueriesScope = @{ }
$Global:UserManagedIdentityResourceId
$Global:RoleDefinitionIdsofInterest = @(
    $AzureConnectedMachineOnboardingRole,
    $VirtualMachineContributorRole,
    $LogAnalyticsContributorRole,
    $LogAnalyticsReaderRole,
    $AutomationOperatorRole,
    $ScheduledPatchingContributorRole,
    $ContributorRole )

function Write-Telemetry {
    <#
    .Synopsis
        Writes telemetry to the job logs.
        Telemetry levels can be "Informational", "Warning", "Error" or "Verbose".
    
    .PARAMETER Message
        Log message to be written.
    
    .PARAMETER Level
        Log level.

    .EXAMPLE
        Write-Telemetry -Message Message -Level Level.
    #>
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Message,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateScript({ $_ -in $TelemetryLevels })]
        [String]$Level = $Informational
    )
	
    if ($Level -eq $Warning) {
        Write-Warning $Message
    }
    elseif ($Level -eq $ErrorLvl) {
        Write-Error $Message
    }
    else {
        Write-Verbose $Message -Verbose
    }
}

function Parse-ArmId {
    <#
        .SYNOPSIS
            Parses ARM resource id.
    
        .DESCRIPTION
            This function parses ARM id to return subscription, resource group, resource name, etc.
    
        .PARAMETER ResourceId
            ARM resourceId of the machine.      
    
        .EXAMPLE
            Parse-ArmId -ResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )
	
    $parts = $ResourceId.Split("/")
    return @{
        Subscription     = $parts[2]
        ResourceGroup    = $parts[4]
        ResourceProvider = $parts[6]
        ResourceType     = $parts[7]
        ResourceName     = $parts[8]
    }
}

function Invoke-RetryWithOutput {
    <#
        .SYNOPSIS
            Generic retry logic.
    
        .DESCRIPTION
            This command will perform the action specified until the action generates no errors, unless the retry limit has been reached.
    
        .PARAMETER Command
            Accepts an Action object.
            You can create a script block by enclosing your script within curly braces.     
    
        .PARAMETER Retry
            Number of retries to attempt.
    
        .PARAMETER Delay
            The maximum delay (in seconds) between each attempt. The default is 5 seconds.
    
        .EXAMPLE
            $cmd = { If ((Get-Date) -lt (Get-Date -Second 59)) { Get-Object foo } Else { Write-Host 'ok' } }
            Invoke-RetryWithOutput -Command $cmd -Retry 61
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [ScriptBlock]$Command,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Retry = 3,
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Delay = 5
    )
	
    $ErrorActionPreferenceToRestore = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
	
    for ($i = 0; $i -lt $Retry; $i++) {
        $exceptionMessage = ""
        try {
            Write-Telemetry -Message ("[Debug]Command [{0}] started. Retry: {1}." -f $Command, ($i + 1) + $ForwardSlashSeparator + $Retry)
            $output = Invoke-Command $Command
            Write-Telemetry -Message ("[Debug]Command [{0}] succeeded." -f $Command)
            $ErrorActionPreference = $ErrorActionPreferenceToRestore
            return $output
        }
        catch [Exception] {
            $exceptionMessage = $_.Exception.Message
			
            if ($Global:Error.Count -gt 0) {
                $Global:Error.RemoveAt(0)
            }
			
            if ($i -eq ($Retry - 1)) {
                $message = ("[Debug]Command [{0}] failed even after [{1}] retries. Exception message:{2}." -f $command, $Retry, $exceptionMessage)
                Write-Telemetry -Message $message -Level $ErrorLvl
                $ErrorActionPreference = $ErrorActionPreferenceToRestore
                throw $message
            }
			
            $exponential = [math]::Pow(2, ($i + 1))
            $retryDelaySeconds = ($exponential - 1) * $Delay # Exponential Backoff Max == (2^n)-1
            Write-Telemetry -Message ("[Debug]Command [{0}] failed. Retrying in {1} seconds, exception message:{2}." -f $command, $retryDelaySeconds, $exceptionMessage) -Level $Warning
            Start-Sleep -Seconds $retryDelaySeconds
        }
    }
}

function Invoke-AzRestApiWithRetry {
    <#
        .SYNOPSIS
            Wrapper around Invoke-AzRestMethod.
    
        .DESCRIPTION
            This function calls Invoke-AzRestMethod with retries.
    
        .PARAMETER Params
            Parameters to the cmdlet.

        .PARAMETER Payload
            Payload.

        .PARAMETER Retry
            Number of retries to attempt.
    
        .PARAMETER Delay
            The maximum delay (in seconds) between each attempt. The default is 5 seconds.
            
        .EXAMPLE
            Invoke-AzRestApiWithRetry -Params @{SubscriptionId = "xxxx" ResourceGroup = "rgName" ResourceName = "resourceName" ResourceProvider = "Microsoft.Compute" ResourceType = "virtualMachines"} -Payload "{'location': 'westeurope'}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [System.Collections.Hashtable]$Params,
        [Parameter(Mandatory = $false, Position = 2)]
        [Object]$Payload = $null,
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Retry = 3,
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateRange(0, [UInt32]::MaxValue)]
        [UInt32]$Delay = 5
    )
	
    if ($Payload) {
        [void]$Params.Add('Payload', $Payload)
    }
	
    $retriableErrorCodes = @(429)
	
    for ($i = 0; $i -lt $Retry; $i++) {
        $exceptionMessage = ""
        $paramsString = $Params | ConvertTo-Json -Compress -Depth $MaxDepth | ConvertFrom-Json
        try {
            Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod started with params [{0}]. Retry: {1}." -f $paramsString, ($i + 1) + $ForwardSlashSeparator + $Retry)
            $output = Invoke-AzRestMethod @Params -ErrorAction Stop
            $outputString = $output | ConvertTo-Json -Compress -Depth $MaxDepth | ConvertFrom-Json
            if ($retriableErrorCodes.Contains($output.StatusCode) -or $output.StatusCode -ge 500) {
                if ($i -eq ($Retry - 1)) {
                    $message = ("[Debug]Invoke-AzRestMethod with params [{0}] failed even after [{1}] retries. Failure reason:{2}." -f $paramsString, $Retry, $outputString)
                    Write-Telemetry -Message $message -Level $ErrorLvl
                    return Process-ApiResponse -Response $output
                }
				
                $exponential = [math]::Pow(2, ($i + 1))
                $retryDelaySeconds = ($exponential - 1) * $Delay # Exponential Backoff Max == (2^n)-1
                Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] failed with retriable error code. Retrying in {1} seconds, Failure reason:{2}." -f $paramsString, $retryDelaySeconds, $outputString) -Level $Warning
                Start-Sleep -Seconds $retryDelaySeconds
            }
            else {
                Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] succeeded. Output: [{1}]." -f $paramsString, $outputString)
                return Process-ApiResponse -Response $output
            }
        }
        catch [Exception] {
            $exceptionMessage = $_.Exception.Message
            Write-Telemetry -Message ("[Debug]Invoke-AzRestMethod with params [{0}] failed with an unhandled exception: {1}." -f $paramsString, $exceptionMessage) -Level $ErrorLvl
            throw
        }
    }
}

function Invoke-ArmApi-WithPath {
    <#
        .SYNOPSIS
            The function prepares payload for Invoke-AzRestMethod
    
        .DESCRIPTION
            This function prepares payload for Invoke-AzRestMethod.
    
        .PARAMETER Path
            ARM API path.

        .PARAMETER ApiVersion
            API version.

        .PARAMETER Method
            HTTP method.

        .PARAMETER Payload
            Paylod for API call.
    
        .EXAMPLE
            Invoke-ArmApi-WithPath -Path "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Compute/virtualMachines/{vmName}/start" -ApiVersion "2023-03-01" -method "PATCH" -Payload "{'location': 'westeurope'}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Path,
        [Parameter(Mandatory = $true, Position = 2)]
        [String]$ApiVersion,
        [Parameter(Mandatory = $true, Position = 3)]
        [ValidateScript({ $_ -in $HttpMethods })]
        [String]$Method,
        [Parameter(Mandatory = $false, Position = 4)]
        [Object]$Payload = $null
    )
	
    $PathWithVersion = "{0}?api-version={1}"
    if ($Path.Contains("?")) {
        $PathWithVersion = "{0}&api-version={1}"
    }
	
    $Uri = ($PathWithVersion -f $Path, $ApiVersion)
    $Params = @{
        Path   = $Uri
        Method = $Method
    }
	
    return Invoke-AzRestApiWithRetry -Params $Params -Payload $Payload
}

function Process-ApiResponse {
    <#
        .SYNOPSIS
            Process API response and returns data.
    
        .PARAMETER Response
            Response object.
    
        .EXAMPLE
            Process-ApiResponse -Response {"StatusCode": 200, "Content": "{\"properties\": {\"location\": \"westeurope\"}}" }
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [Object]$Response
    )
	
    $content = $null
    if ($Response.Content) {
        $content = ConvertFrom-Json $Response.Content
    }
	
    if ($Response.StatusCode -eq 200) {
        return @{
            Status       = $Succeeded
            Response     = $content
            ErrorCode    = [String]::Empty
            ErrorMessage = [String]::Empty
        }
    }
    elseif ($Response.StatusCode -eq 204) {
        return @{
            Status       = $Succeeded
            Response     = $content
            ErrorCode    = [String]::Empty
            ErrorMessage = [String]::Empty
        }
    }
    else {
        $errorCode = $Unknown
        $errorMessage = $Unknown
        if ($content.error) {
            $errorCode = ("{0}/{1}" -f $Response.StatusCode, $content.error.code)
            $errorMessage = $content.error.message
        }
		
        return @{
            Status       = $Failed
            Response     = $content
            ErrorCode    = $errorCode
            ErrorMessage = $errorMessage
        }
    }
}

function Get-MachinesFromLogAnalytics {
    <#
        .SYNOPSIS
            Gets machines onboarded to updates solution from Log Analytics Workspace.
    
        .DESCRIPTION
            This command will return machines onboarded to UM from LA workspace.

        .PARAMETER ResourceId
            Resource Id.

        .EXAMPLE
            Get-MachinesFromLogAnalytics -ResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$ResourceId
    )
	
    $armComponents = Parse-ArmId -ResourceId $ResourceId
    $script = {
        Set-AzContext -Subscription $armComponents.Subscription
        $Workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $armComponents.ResourceGroup -Name $armComponents.ResourceName
        $QueryResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $Workspace.CustomerId -Query $MachinesOnboaredToAutomationUpdateManagementQuery -ErrorAction Stop
        return $QueryResults
    }
	
    $output = Invoke-RetryWithOutput -command $script
    return $output
}

function Populate-AllMachinesOnboardedToUpdateManagement {
    <#
        .SYNOPSIS
            Gets all machines onboarded to Update Management under this automation account.
    
        .DESCRIPTION
            This function gets all machines onboarded to Automation Update Management under this automation account using Log Analytics Workspace.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
    
        .EXAMPLE
            Populate-AllMachinesOnboardedToUpdateManagement -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
	
    try {
        $linkedWorkspace = Invoke-ArmApi-WithPath -Path ($LinkedWorkspacePath -f $AutomationAccountResourceId) -ApiVersion $AutomationApiVersion -Method $GET
        $laResults = Get-MachinesFromLogAnalytics -ResourceId $linkedWorkspace.Response.Id
        if ($laResults.Results.Count -eq 0 -and $null -eq $laResults.Error) {
            Write-Telemetry -Message ("Zero machines retrieved from Log Analytics Workspace. If machines were recently onboarded, please wait for few minutes for machines to start reporting to Log Analytics Workspace") -Level $ErrorLvl
            throw
        }
        elseif ($laResults.Results.Count -gt 0 -or @($laResults.Results).Count -gt 0) {
            Write-Telemetry -Message ("Retrieved machines from Log Analytics Workspace.")
			
            foreach ($record in $laResults.Results) {
				
                if ($record.ResourceType -eq $ArcVMResourceType -or $record.ResourceType -eq $VMResourceType) {
                    [void]$Global:Machines.Add($record.ResourceId)
                }
            }
        }
        else {
            Write-Telemetry -Message ("Failed to get machines from Log Analytics Workspace with error {0}." -f $laResults.Error) -Level $ErrorLvl
            throw
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled exception {0}." -f , $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Get-AllSoftwareUpdateConfigurations {
    <#
        .SYNOPSIS
            Gets all software update configurations.
    
        .DESCRIPTION
            This function gets all software update configurations with support for pagination.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
            
        .EXAMPLE
            Get-AllSoftwareUpdateConfigurations -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
    $output = $null
    $skip = 0
    do {
        $path = ($SoftwareUpdateConfigurationsPath -f $AutomationAccountResourceId, $skip)
        $output = Invoke-ArmApi-WithPath -Path $path -ApiVersion $SoftwareUpdateConfigurationApiVersion -Method $GET
        if ($output.Status -eq $Failed) {
            Write-Telemetry -Message ("Failed to get software update configurations with error code {0} and error message {1}." -f $output.ErrorCode, $output.ErrorMessage)
            throw
        }
        foreach ($result in $output.Response.value) {
            if (!$Global:SoftwareUpdateConfigurationsResourceIDs.ContainsKey($result.id)) {
                $Global:SoftwareUpdateConfigurationsResourceIDs[$result.id] = $result.name
            }
        }
        # API paginates in multiples of 100.
        $skip = $skip + 100
    }
    while ($null -ne $output.Response.nextLink);
}

function Delete-RoleAssignmentsForAzureDynamicMachinesScope {
    <#
        .SYNOPSIS
            Deletes required roles assignments for Azure dynamic machines scope.
    
        .DESCRIPTION
            This command will delete required roles assignments for Azure dynamic machines scope.

        .PARAMETER AutomationAccountResourceId
            Automation Account Resource Id.

        .EXAMPLE
            Delete-RoleAssignmentsForAzureDynamicMachinesScope -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
    Get-AllSoftwareUpdateConfigurations -AutomationAccountResourceId $AutomationAccountResourceId
	
    $softwareUpdateConfigurations = [System.Collections.ArrayList]@($Global:SoftwareUpdateConfigurationsResourceIDs.Keys)
	
    foreach ($softwareUpdateConfiguration in $softwareUpdateConfigurations) {
        try {
            $softwareUpdateConfigurationData = Invoke-ArmApi-WithPath -Path $softwareUpdateConfiguration -ApiVersion $SoftwareUpdateConfigurationApiVersion -Method $GET
            if ($softwareUpdateConfigurationData.Status -eq $Failed) {
                Write-Telemetry -Message ("Failed to get software update configuration {0} with error code {1} and error message {2}." -f $softwareUpdateConfiguration, $softwareUpdateConfigurationData.ErrorCode, $softwareUpdateConfigurationData.ErrorMessage) -Level $ErrorLvl
            }
            elseif ($null -ne $softwareUpdateConfigurationData.Response.properties.updateConfiguration.targets.azureQueries) {
                foreach ($azureQuery in $softwareUpdateConfigurationData.Response.properties.updateConfiguration.targets.azureQueries) {
                    foreach ($scope in $azureQuery.scope) {
                        try {
                            if (!$Global:AzureDynamicQueriesScope.ContainsKey($scope)) {
                                $scopeAtSubscriptionLevel = $scope.Split("/")

                                # Delete assigned roles at subscription level.
                                Delete-Roles -Scope ("/subscriptions/" + $scopeAtSubscriptionLevel[2])
								
                                # Save in dictionary to avoid deleting roles for the same scope again.
                                $Global:AzureDynamicQueriesScope[$scope] = $true
                            }
                        }
                        catch [Exception] {
                            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
                        }
                    }
                }
            }
        }
        catch [Exception] {
            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        }
    }
}

function Delete-RoleAssignmentsForMachines {
    <#
        .SYNOPSIS
            Deletes required roles assignments for machines.
    
        .DESCRIPTION
            This command will delete required roles assignments for machines.

        .EXAMPLE
            Delete-RoleAssignmentsForMachines
    #>
    foreach ($machine in $Global:Machines) {
        try {
            # Delete roles assigned at machine scope.
			Delete-Roles -Scope $machine
        }
        catch [Exception] {
            Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        }
    }
}

function Delete-RoleAssignmentsForAutomationAccountAndLinkedLogAnalyticsWorkspace {
    <#
        .SYNOPSIS
            Deletes required roles assignments for automation account and linked log analytics workspace.
    
        .DESCRIPTION
            This command will delete required roles assignments for automation account and linked log analytics workspace.

        .PARAMETER AutomationAccountResourceId
            Automation Account Resource Id.

        .EXAMPLE
            Delete-RoleAssignmentsForAutomationAccountAndLinkedLogAnalyticsWorkspace -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
	
    $parts = $AutomationAccountResourceId.Split("/")
		
    # Delete role assignments at automation account subscription scope.
    Delete-Roles -Scope ("/subscriptions/{0}" -f $parts[2])

    $response = Invoke-ArmApi-WithPath -Path ($LinkedWorkspacePath -f $AutomationAccountResourceId) -ApiVersion $AutomationApiVersion -Method $GET
	
    if ($response.Status -eq $Failed) {
        Write-Telemetry -Message ("Failed to get linked Log Analytics Workspace for {0}." -f $AutomationAccountResourceId) -Level $ErrorLvl
        throw
    }

    $linkedWorkspace = $response.Response.Id
    $parts = $linkedWorkspace.Split("/")

    # Delete role assignments at log analytics subscription scope.
    Delete-Roles -Scope ("/subscriptions/{0}" -f $parts[2])
}

function Delete-UserManagedIdentity {
    <#
        .SYNOPSIS
            Delete user managed Identity.
    
        .DESCRIPTION
            This function will delete user managed Identity.
        
        .EXAMPLE
            Delete-UserManagedIdentity -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
	
    try {		
        $response = Invoke-ArmApi-WithPath -Path $Global:UserManagedIdentityResourceId -ApiVersion $UserManagedIdentityApiVersion -Method $DELETE
		
        if ($response.Status -eq $Failed) {
            Write-Telemetry -Message ("Failed to delete user managed identity {0}." -f $Global:UserManagedIdentityResourceId) -Level $ErrorLvl
            throw
        }
        else {
            Write-Telemetry -Message ("Successfully deleted user managed identity with {0}." -f , $Global:UserManagedIdentityResourceId)
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

function Remove-MigrationUserManagedIdentityFromAutomationAccount {
    <#
        .SYNOPSIS
            Removes migration user managed Identity from the automation account.
    
        .DESCRIPTION
            This function will remove migration user managed Identity from the automation account.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
    
        .EXAMPLE
            Remove-MigrationUserManagedIdentityFromAutomationAccount -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
	
    try {
		
        $response = Invoke-ArmApi-WithPath -Path $AutomationAccountResourceId -ApiVersion $AutomationApiVersion -Method $GET
        $userManagedIdentityPayload = ConvertFrom-Json $RemoveMigrationUserManagedIdentityFromAutomationAccountPayload
		$parts = $AutomationAccountResourceId.Split("/")
        $Global:UserManagedIdentityResourceId = ($UserManagedIdentityPath -f $parts[2], $parts[4], $parts[8] + "_AUMMig_uMSI")
        $userManagedIdentities = @{ }

        # Honour the current identity settings for the automation account.
        if ($response.Response.identity.userAssignedIdentities.psobject.properties.Value.Count -eq 1 -and $response.Response.identity.type -Match "systemassigned") {            
            $userManagedIdentityPayload.identity.type = "systemassigned"
        }
        elseif ($response.Response.identity.userAssignedIdentities.psobject.properties.Value.Count -eq 1) {
            $userManagedIdentityPayload.identity.type = "none"
        }
        elseif ($response.Response.identity.userAssignedIdentities.psobject.properties.Value.Count -gt 1) {
            $userManagedIdentityPayload.identity.type = $response.Response.identity.type
            # Add the user managed identity for migration.
            [void]$userManagedIdentities.Add($Global:UserManagedIdentityResourceId, $null)
            $userManagedIdentityPayload.identity | Add-Member -MemberType NoteProperty -Name "userAssignedIdentities" -Value $userManagedIdentities
        }
        elseif ($response.Response.identity.type -Match "systemassigned") {
            $userManagedIdentityPayload.identity.type = "systemassigned"
        }
        else {
            $userManagedIdentityPayload.identity.type = "none"
        }

        $userManagedIdentityPayload = ConvertTo-Json $userManagedIdentityPayload -Depth $MaxDepth
		
        $response = Invoke-ArmApi-WithPath -Path $AutomationAccountResourceId -ApiVersion $AutomationApiVersion -Method $PATCH -Payload $userManagedIdentityPayload
        if ($response.Status -eq $Failed) {
            Write-Telemetry -Message ("Failed to remove user managed identity with error code {0} and error message {1}." -f $response.ErrorCode, $response.ErrorMessage) -Level $ErrorLvl
            throw
        }
        else {
            Write-Telemetry -Message ("Successfully removed user managed identity {0} to automation account {1}." -f , $Global:UserManagedIdentityResourceId, $Global:AutomationAccountRegion)
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
    }
}

function Delete-AutomationAccountAzureEnvironmentVariable {
    <#
        .SYNOPSIS
            Deletes Azure environment variable for the automation account.
    
        .DESCRIPTION
            This function will delete Azure environment variable for the automation account.
    
        .PARAMETER AutomationAccountResourceId
            Automation account resource id.
            
        .EXAMPLE
            Delete-AutomationAccountAzureEnvironmentVariable -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}"
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$AutomationAccountResourceId
    )
    try {
        $response = Invoke-ArmApi-WithPath -Path ($AutomationVariablePath -f $AutomationAccountResourceId) -ApiVersion $AutomationVariableApiVersion -Method $DELETE
        if ($response.Status -eq $Failed) {
            Write-Telemetry -Message ("Failed to delete variable AutomationAccountAzureEnvironment from automation account.") -Level $ErrorLvl
        }
        else {
            Write-Telemetry -Message ("Deleted variable AutomationAccountAzureEnvironment from automation account.")
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
    }
}

function Delete-Roles {
    <#
        .SYNOPSIS
            Deletes role assignments for the Scope specified.
    
        .DESCRIPTION
            This command will delete role assignments for the Scope specified.

        .PARAMETER Scope
            Scope.
        
        .EXAMPLE
            Delete-Roles -Scope Scope
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$Scope
    )
	
    try {

        $response = Invoke-ArmApi-WithPath -Path $Global:UserManagedIdentityResourceId -ApiVersion $UserManagedIdentityApiVersion -Method $GET
        if ($response.Status -eq $Succeeded)
        {
            $userManagedIdentityPrincipalId = $response.Response.properties.principalId
        }
        else {
            Write-Telemetry -Message ("Failed to get principal id with error {0} and error message {1} for {2}." -f $response.ErrorCode, $response.ErrorMessage, $ResourceId)
            throw
        }

        $response = Invoke-ArmApi-WithPath -Path ($AzureListRoleAssignmentsPath -f $Scope, $userManagedIdentityPrincipalId) -ApiVersion $AzureRoleAssignmentsApiVersion -Method $GET
		if ($response.Status -eq $Failed) {
            Write-Telemetry -Message ("Failed to get role assignments with error code {0} and error message {1} for {2}." -f $response.ErrorCode, $response.ErrorMessage, $ResourceId)
            throw
        }
        foreach ($roles in $response.Response.value) {
            try {
                $scope = $roles.properties.scope
                $name = $roles.name
                $roleDefinitionId = ($roles.properties.roleDefinitionId).Split("/")[6]
                $principalId = $roles.properties.principalId

                if ($Global:RoleDefinitionIdsofInterest -contains $roleDefinitionId -and $userManagedIdentityPrincipalId -eq $principalId) {
                    $output = Invoke-ArmApi-WithPath -Path $roles.id -ApiVersion $AzureRoleAssignmentsApiVersion -Method $DELETE
                    if ($output.Status -eq $Failed) {
                        Write-Telemetry -Message ("Failed to delete role {0} over scope {1}." -f , $name, $scope) -Level $ErrorLvl                    
                    }
                    else {
                        Write-Telemetry -Message ("Deleted role {0} over scope {1}." -f , $name, $scope)
                    }                        
                }
            }
            catch [Exception] {
                Write-Telemetry -Message ("Unhandled exception while deleting role {0} over scope {1}." -f , $name, $scope) -Level $ErrorLvl
            }
        }
    }
    catch [Exception] {
        Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
        throw
    }
}

$azConnect = Connect-AzAccount -SubscriptionId $AutomationAccountResourceId.Split("/")[2] -Environment $AutomationAccountAzureEnvironment
if ($null -eq $azConnect) {
    Write-Telemetry -Message ("Failed to connect to azure in first attempt. Will retry with DeviceCodeAuthentication.") -Level $ErrorLvl
    $azConnect = Connect-AzAccount -UseDeviceAuthentication -SubscriptionId $AutomationAccountResourceId.Split("/")[2] -Environment $AutomationAccountAzureEnvironment
    if ($null -eq $azConnect) {
        Write-Telemetry -Message ("Failed to connect to azure with DeviceCodeAuthentication also.") -Level $ErrorLvl
        throw
    }
}
else {
    Write-Telemetry -Message ("Successfully connected with account {0} to subscription {1}" -f $azConnect.Context.Account, $azConnect.Context.Subscription)
}

try {
    # Retrieve all machines onboarded to Azure Automation Update Management.
    Populate-AllMachinesOnboardedToUpdateManagement -AutomationAccountResourceId $AutomationAccountResourceId
    
    # Delete variable AutomationAccountAzureEnvironment from the Automation Account.
    Delete-AutomationAccountAzureEnvironmentVariable -AutomationAccountResourceId $AutomationAccountResourceId
	
    # Remove migration user-managed identity from the automation account.
    Remove-MigrationUserManagedIdentityFromAutomationAccount -AutomationAccountResourceId $AutomationAccountResourceId
	
    # Delete roles assigned to user-managed identity.
    Delete-RoleAssignmentsForAutomationAccountAndLinkedLogAnalyticsWorkspace -AutomationAccountResourceId $AutomationAccountResourceId
    Delete-RoleAssignmentsForMachines
    Delete-RoleAssignmentsForAzureDynamicMachinesScope -AutomationAccountResourceId $AutomationAccountResourceId

    # Delete the migration user-managed identity.
    Delete-UserManagedIdentity -AutomationAccountResourceId $AutomationAccountResourceId
		
    Write-Output ("Cleanup done successfully for automation account {0}." -f $AutomationAccountResourceId)
}
catch [Exception] {
    Write-Telemetry -Message ("Unhandled Exception {0}." -f $_.Exception.Message) -Level $ErrorLvl
}