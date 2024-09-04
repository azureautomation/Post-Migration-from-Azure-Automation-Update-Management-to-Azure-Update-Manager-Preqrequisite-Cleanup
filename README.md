# Post-Migration-from-Azure-Automation-Update-Management-to-Azure-Update-Manager-Preqrequisite-Cleanup
This Powershell script will delete all role assignments and delete user managed identity created for migration of machines and software update configurations from Azure Automation Update Management to Azure Update Manager.


### DESCRIPTION
This script will do the following:
1. Retrieve all machines onboarded to Azure Automation Update Management under this automation account from linked Log Analytics Workspace.
2. Delete an automation variable with name AutomationAccountAzureEnvironment created for use in migration.
3. Remove the user managed identity from the automation account
4. Delete assigned roles to the user managed identity.
5. Delete the user managed identity.

The executor of the script should have Microsoft.Authorization/roleAssignments/write action such as Role Based Access Control Administrator on the scopes on which access will be revoked to user managed identity. 

### PARAMETER AutomationAccountResourceId
        Mandatory
        Automation Account Resource Id.

### PARAMETER AutomationAccountAzureEnvironment
        Mandatory
        Azure Cloud Environment to which Automation Account belongs.
        Accepted values are AzureCloud, AzureUSGovernment, AzureChinaCloud.

### EXAMPLE
        MigrationPrerequisitesCleanup -AutomationAccountResourceId "/subscriptions/{subId}/resourceGroups/{rgName}/providers/Microsoft.Automation/automationAccounts/{aaName}" -AutomationAccountAzureEnvironment "AzureCloud"

### OUTPUTS
        The role assignments and user managed identity deleted.