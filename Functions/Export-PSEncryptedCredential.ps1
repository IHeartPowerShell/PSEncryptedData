function Export-PSEncryptedCredential
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
		[Parameter(Mandatory,ParameterSetName='Path')]
        [Parameter(Mandatory,ParameterSetName='Thumbprint')]
        [Parameter(Mandatory,ParameterSetName='Certificate')]
        [System.Management.Automation.Credential()]
        [ValidateNotNull()]
        [PSCredential] $Credential,

        [Parameter(Mandatory,ParameterSetName='Path')]
        [Parameter(Mandatory,ParameterSetName='Thumbprint')]
        [Parameter(Mandatory,ParameterSetName='Certificate')]
        [ValidateNotNullOrEmpty()]
        [string] $OutputPath,

        [Parameter(Mandatory, ParameterSetName='Path')]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [Parameter(Mandatory, ParameterSetName='Thumbprint')]
        [ValidateNotNullOrEmpty()]
        [string] $Thumbprint,

        [Parameter(Mandatory, ParameterSetName='Certificate')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [ValidateNotNull()]
        [System.Security.Cryptography.SymmetricAlgorithm] $Provider = ([System.Security.Cryptography.Aes]::Create())
    )

    process
    {
        $PSBoundParameters.Remove('Credential') | Out-Null
        @{UserName=$Credential.UserName;Password=$Credential.GetNetworkCredential().Password} | ConvertTo-Json | Out-String | Export-PSEncryptedData @PSBoundParameters 
    }
}