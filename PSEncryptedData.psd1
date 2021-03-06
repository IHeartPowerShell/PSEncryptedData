@{
# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = '064b42e1-7673-41f2-9953-bf4379a1e951'

RootModule = 'PSEncryptedData.psm1'

# Author of this module
Author = 'Adam Weigert'

# Company or vendor of this module
# CompanyName = ''

# Copyright statement for this module
# Copyright = ''

# Description of the functionality provided by this module
Description = 'The PSEncryptedData module provides encryption/decryption for PowerShell PSCredential and string data utilizing certificate assymetric encryption.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '4.0'

# Functions to export from this module
FunctionsToExport = 'ConvertFrom-PSEncryptedData','ConvertTo-PSEncryptedData','Export-PSEncryptedCredential','Export-PSEncryptedData','Import-PSEncryptedCredential','Import-PSEncryptedData','New-PSEncryptedDataCertificate'
}
