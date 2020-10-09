# KeePass Secret Management Extension

This is a modified version of Justin Grote's module [JustinGrote/SecretManagement.KeePass](https://github.com/JustinGrote/SecretManagement.KeePass).

## Modifications
- Set-Secret
  - Will now update an existing secret in addition to adding a secret
- Added support for the following VaultParameters
  - DefaultEntryGroupPath : If set tells Keepass which group to add the secret to
  - MasterKeyVault : The SecretManagement Vault that the Master Key is stored in
  - MasterKeySecretName : The name of the Secret that stores the Master Key

### Why MasterKeyVault and MasterKeySecretName? 
In order to fully automate the change of password in the Keepass database.

The MasterKeyVault must be a vault already registered with SecretManagement and the MasterKeySecretName must already exist in the vault.

### Quick Start

1. Create a keepass database with a master password
2. Download or clone the repository to your local machine.
3. Run the following command to register the vault. 
   
   At minimum, you need to specify the path to the Keepass database.
    ``` powershell
    Register-SecretVault -Name 'testVault' -ModuleName 'module name or path if not in the Powershell module path' -VaultParameters @{
        Path = "path/to/my/vault.kdbx"
    }
    ```
    Example using additional vault parameters:
    ``` powershell
    Register-SecretVault -Name 'testVault' -ModuleName 'module name or path if not in the Powershell module path' -VaultParameters @{
        Path = 'path/to/my/vault.kdbx'
        DefaultEntryGroupPath = 'path/to/group'
        MasterKeyVault = 'CredMan'
        MasterKaySecretName = 'keepassMK'
    }
    ```    
4. List and create secrets as normal

### Current Limitations
1. Only supports PSCredential, String and SecureString
2. Only supports master password protected keepass databases