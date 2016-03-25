function Export-PSEncryptedData
{
    [OutputType([void])]
    [CmdletBinding()]
    param
    (
		[Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Path')]
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Thumbprint')]
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Certificate')]
        [ValidateNotNull()]
        $InputObject,

        [Parameter(Mandatory,Position=0,ParameterSetName='Path')]
        [Parameter(Mandatory,Position=0,ParameterSetName='Thumbprint')]
        [Parameter(Mandatory,Position=0,ParameterSetName='Certificate')]
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

        [ValidateSet('ASCII','BigEndianUnicode','Default','Unicode','UTF7','UTF8','UTF32')]
        [string] $Encoding = 'Default',

        [ValidateNotNull()]
        [System.Security.Cryptography.SymmetricAlgorithm] $Provider = ([System.Security.Cryptography.Aes]::Create())
    )

    process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            'Path' 
            {
                if (Test-Path -Path $Path -PathType Leaf)
                {
                    $Certificate = (Get-Item -Path $Path) -as [System.Security.Cryptography.X509Certificates.X509Certificate2]

                    if (!$Certificate)
                    {
                        Write-Error "The path '$($Path)' is not a valid x509 certificate." -ErrorAction Stop
                    }
                }
                else
                {
                    Write-Error "The path '$($Path)' could not be found or access is denied." -ErrorAction Stop
                }
            }

            'Thumbprint'
            {
                if (Test-Path -Path "Cert:\CurrentUser\My\$($Thumbprint)" -PathType Leaf)
                {
                    $Certificate = Get-Item -Path "Cert:\CurrentUser\My\$($Thumbprint)"
                }
                elseif (Test-Path -Path "Cert:\LocalMachine\My\$($Thumbprint)" -PathType Leaf)
                {
                    $Certificate = Get-Item -Path "Cert:\LocalMachine\My\$($Thumbprint)"
                }
                else
                {
                    Write-Error "The certificate '$($Thumbprint)' could not be found or access is denied." -ErrorAction Stop
                }

                if (!$Certificate)
                {
                    Write-Error "Failed to retrieve certificate '$($Thumbprint)' or access is denied." -ErrorAction Stop
                }
            }

            'Certificate' {}
        }

        Write-Verbose "Certificate '$($Certificate.Subject)' with thumbprint '$($Certificate.Thumbprint)' will be used for encryption."

        $InputObject | ConvertTo-PSEncryptedData -Certificate $Certificate -Encoding $Encoding -Provider $Provider | Out-File -FilePath $OutputPath -Encoding $Encoding
    }
}