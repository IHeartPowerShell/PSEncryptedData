function ConvertTo-PSEncryptedData
{
    [OutputType([string])]
    [CmdletBinding(DefaultParameterSetName='Path')]
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,Position=0,ParameterSetName='Path')]
        [Parameter(Mandatory,ValueFromPipeline,Position=0,ParameterSetName='Thumbprint')]
        [Parameter(Mandatory,ValueFromPipeline,Position=0,ParameterSetName='Certificate')]
        [ValidateNotNull()]
        $InputObject,

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

        $Key        = $Certificate.PublicKey.Key.Encrypt($Provider.Key, $true)
        $Transform  = $Provider.CreateEncryptor()
        $DataStream = New-Object System.IO.MemoryStream
        $Stream     = New-Object System.Security.Cryptography.CryptoStream ($DataStream, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $Writer     = New-Object System.IO.StreamWriter ($Stream, ([System.Text.Encoding]::$Encoding))

        if ($InputObject -is [SecureString])
        {
            $Writer.Write((New-Object PSCredential 'USERNAME',$InputObject).GetNetworkCredential().Password)
        }
        else
        {
            $Writer.Write($InputObject.ToString())
        }

        $Writer.Flush()
        $Writer.Close()
        
        $Obj  = @{
            Certificate = $Certificate.Thumbprint
            Encoding    = $Encoding
            Provider    = @{
                Type = $Provider.GetType().FullName
                Key  = [Convert]::ToBase64String($Key)
                IV   = [Convert]::ToBase64String($Provider.IV)
                BlockSize    = $Provider.BlockSize
                FeedbackSize = $Provider.FeedbackSize
                KeySize      = $Provider.KeySize
                Mode         = $Provider.Mode.ToString()
                Padding      = $Provider.Padding.ToString()
            }
            Data = [Convert]::ToBase64String($DataStream.ToArray())
        } 

        $Json = $Obj | ConvertTo-Json -Compress
        $Data = [System.Text.Encoding]::ASCII.GetBytes($Json)

        [Convert]::ToBase64String($Data)
    }
}
