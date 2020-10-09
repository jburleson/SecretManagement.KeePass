# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using namespace Microsoft.PowerShell.SecretManagement

function Get-KeepassParams {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName, 

        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [hashtable]$AdditionalParameters
    )
    # Set local vault parameters based on the parameters passed in
    $KeepassParams = @{}

    if ($VaultName) { 
        $KeepassParams.DatabaseProfileName = $VaultName 
    }
    # Check to see if a default keepass group has been set
    if ($AdditionalParameters.DefaultEntryGroupPath) { 
        $KeepassParams.KeePassEntryGroupPath = $AdditionalParameters.DefaultEntryGroupPath 
    }
    <#  MasterKey options
        Option 1) Master Key is stored in a different SecretManagement Vault
            Two pieces of information needed: VaultName and Secret Name
            Secret is retrieved by first importing the the Vault extension using a set prefix. If you do not import the extension module,
            the call Get-Secret will use the funtion in this module instead of the function from Microsoft.Powershell.SecretManagement.
        Option 2) Prompt user for Master Key 
    #>
    if ($AdditionalParameters.MasterKeyVault) { 
        try{
            $vaultModuleInfo = Get-SecretVault -name $AdditionalParameters.MasterKeyVault
            $importPath = Get-ChildItem -Path $vaultModuleInfo.ModulePath -Recurse -Directory -Filter "$($vaultModuleInfo.ModuleName).Extension"
            Import-Module -Name $importPath -Prefix 'LS' -ErrorAction Stop
            $KeepassParams.MasterKey = Get-LSSecret -Name $AdditionalParameters.MasterKeySecretName -Vault $AdditionalParameters.MasterKeyVault -ErrorAction Stop
        }catch{
            throw 
        }
    }else{
        $SecureVaultPW = (Get-Variable -Scope Script -Name "Vault_$VaultName" -ErrorAction SilentlyContinue).Value.Password
        if (-not $SecureVaultPW) { 
            throw "${VaultName}: Error retrieving the master key from cache" 
        }
        $KeePassParams.MasterKey = $SecureVaultPW
    }
    
    return $KeepassParams
}

function Get-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters
    )

    $KeepassParams = Get-KeepassParams $VaultName $AdditionalParameters

    $keepassGetResult = Get-KeePassEntry @KeepassParams -Title $Name| Where-Object ParentGroup -NotMatch 'RecycleBin'
    if ($keepassGetResult.count -gt 1) { 
        throw "Multiple ambiguous entries found for $Name, please remove the duplicate entry" 
    }
    if (-not $keepassGetResult.Username) {
        $keepassGetResult.Password
    }
    else {
        [PSCredential]::new($KeepassGetResult.UserName, $KeepassGetResult.Password)
    }
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [object]$Secret,

        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters
    )

    $KeepassParams = Get-KeepassParams $VaultName $AdditionalParameters

    #Set default group if one was not specified for the vault
    if (-not $KeepassParams.ContainsKey('KeePassEntryGroupPath')) {
        [string]$KeepassParams.KeePassEntryGroupPath = Get-KeePassGroup @KeepassParams | 
            Where-Object fullpath -notmatch '/' | ForEach-Object fullpath | Select-Object -first 1
    }

    $kpEntry = Get-KeePassEntry @KeepassParams -Title $Name | Where-Object ParentGroup -notmatch 'RecycleBin' 

    switch ($Secret.GetType()) {
        ([string]) {
            $KeepassParams.KeepassPassword = ConvertTo-SecureString $Secret -AsPlainText -Force
        }
        ([securestring]) {
            $KeepassParams.KeepassPassword = $Secret    
        }
        ([pscredential]) {
            $KeepassParams.Username = $Secret.Username
            $KeepassParams.KeepassPassword = $Secret.Password
        }
        default {
            throw 'This vault provider only accepts strings, secure strings and PSCredential secrets'
        }
    }
    if($null -ne $kpEntry){
        # Update existing entry
        $KeepassParams.KeePassEntry = $kpEntry
        $result = [bool](Update-KeePassEntry @KeepassParams -Title $Name -PassThru -Confirm:$false)
    }else{
        # Create new entry
        $result = [bool](New-KeePassEntry @KeepassParams -Title $Name -PassThru)
    }
    return $result
}

function Remove-Secret {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters
    )

    $KeepassParams = Get-KeepassParams $VaultName $AdditionalParameters

    $GetKeePassResult = Get-KeePassEntry @KeepassParams -Title $Name
    if (-not $GetKeePassResult) { throw "No Keepass Entry named $Name found" }

    # Remove-KeypassEntry does not have a param for the group path so if it is set, remove it
    # to avoid parameter cannot be found error.
    if ($KeepassParams.ContainsKey('KeePassEntryGroupPath')) {
        $KeepassParams.Remove('KeePassEntryGroupPath')
    }    
    Remove-KeePassEntry @KeepassParams -KeePassEntry $GetKeePassResult -ErrorAction stop -Confirm:$false
    return $true
}

function Get-SecretInfo {
    [CmdletBinding()]
    param(
        [string]$Filter,

        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName, 

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters
    )

    if(-not $Filter){
        $Filter = '*'
    }

    $KeepassParams = Get-KeepassParams -VaultName $VaultName -AdditionalParameters $AdditionalParameters

    $KeepassGetResult = Get-KeePassEntry @KeepassParams | Where-Object { $_ -notmatch '^.+?/Recycle Bin/' }

    [Object[]]$secretInfoResult = $KeepassGetResult.where{ 
        $PSItem.Title -like $filter 
    }.foreach{
        [SecretInformation]::new(
            $PSItem.Title, #string name
            [SecretType]::PSCredential, #SecretType type
            $VaultName #string vaultName
        )
    }

    [Object[]]$sortedInfoResult = $secretInfoResult | Sort-Object -Unique Name
    if ($sortedInfoResult.count -lt $secretInfoResult.count) {
        $filteredRecords = (Compare-Object $sortedInfoResult $secretInfoResult | Where-Object SideIndicator -eq '=>').InputObject
        Write-Warning "Vault ${VaultName}: Entries with non-unique titles were detected, the duplicates were filtered out. Duplicate titles are currently not supported with this extension, ensure your entry titles are unique in the database."
        Write-Warning "Vault ${VaultName}: Filtered Non-Unique Titles: $($filteredRecords -join ', ')"
    }
    $sortedInfoResult
}

function Test-SecretVault {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters 
    )

    Write-Verbose "SecretManagement: Testing Vault ${VaultName}"

    if(-not $VaultName){ 
        throw 'Keepass: You must specify a Vault Name to test' 
    }

    if(-not $AdditionalParameters.Path) {
        #TODO: Add ThrowUser to throw outside of module scope
        throw [System.Management.Automation.ItemNotFoundException]::new("Vault $($VaultName): You must specify the Path vault parameter as a path to your KeePass Database")
    }

    if(-not (Test-Path $AdditionalParameters.Path)) {
        throw [System.Management.Automation.ItemNotFoundException]::new("Vault $($VaultName): Could not find the keepass database $($AdditionalParameters.Path). Please verify the file exists or re-register the vault.")
    }

    <#  MasterKey options
        Option 1) Master Key is stored in a different SecretManagement Vault
            Two pieces of information needed: VaultName and Secret Name
            Secret is retrieved by first importing the the Vault extension using a set prefix. If you do not import the extension module,
            the call Get-Secret will use the funtion in this module instead of the function from Microsoft.Powershell.SecretManagement.
        Option 2) Prompt user for Master Key 
    #>
    if($AdditionalParameters.MasterKeyVault){
        if(-not $AdditionalParameters.MasterKeySecretName){
            throw [System.Management.Automation.ItemNotFoundException]::new('Masterkey Vault Name is provided but the Masterkey Secret Name was not')
        }
        try{
            $vaultModuleInfo = Get-SecretVault -name $AdditionalParameters.MasterKeyVault
            $importPath = Get-ChildItem -Path $vaultModuleInfo.ModulePath -Recurse -Directory -Filter "$($vaultModuleInfo.ModuleName).Extension"
            Import-Module -Name $importPath -Prefix 'LS' -ErrorAction Stop
            $KeepassParams.MasterKey = Get-LSSecret -Name $AdditionalParameters.MasterKeySecretName -Vault $AdditionalParameters.MasterKeyVault -ErrorAction Stop
        }catch{
            throw 
        }
    }else{
        try {
            $VaultMasterKey = (Get-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction Stop).Value
            Write-Verbose "Vault ${VaultName}: Master Key found in Cache, skipping user prompt"
        }
        catch {
            $GetCredentialParams = @{
                Username = 'VaultMasterKey'
                Message  = "Enter the Vault Master Password for Vault $VaultName"
            }
            $VaultMasterKey = (Get-Credential @GetCredentialParams)
            if (-not $VaultMasterKey.Password) { throw 'You must specify a vault master key to unlock the vault' }
            Set-Variable -Name "Vault_$VaultName" -Scope Script -Value $VaultMasterKey
        }
    }
    
    if(-not (Get-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName)) {
        New-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName -DatabasePath $AdditionalParameters.Path -UseMasterKey
        Write-Verbose "Vault ${VaultName}: A PoshKeePass database configuration was not found but was created."
        return $true
    }
    try{
        Get-KeePassEntry -DatabaseProfileName $VaultName -MasterKey $VaultMasterKey -Title '__SECRETMANAGEMENT__TESTSECRET_SHOULDNOTEXIST' -ErrorAction Stop
    }
    catch{
        if(-not $AdditionalParameters.MasterKeyVault){
            Clear-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction SilentlyContinue
        }
        throw $PSItem
    }

    #If the above doesn't throw an error, we are good
    return $true
}