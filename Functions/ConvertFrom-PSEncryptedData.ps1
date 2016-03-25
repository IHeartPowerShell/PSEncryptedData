function ConvertFrom-PSEncryptedData
{
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory,ValueFromPipeline,Position=0)]
        [string] $InputObject,

        [switch] $AsSecureString = $false
    )

    process 
    {
        $Data = [Convert]::FromBase64String($InputObject)
        $Json = [System.Text.Encoding]::ASCII.GetString($Data)
        $Obj  = $Json | ConvertFrom-Json

        if (Test-Path -Path "Cert:\CurrentUser\My\$($Obj.Certificate)" -PathType Leaf)
        {
            $Certificate = Get-Item -Path "Cert:\CurrentUser\My\$($Obj.Certificate)"
        }
        elseif (Test-Path -Path "Cert:\LocalMachine\My\$($Obj.Certificate)" -PathType Leaf)
        {
            $Certificate = Get-Item -Path "Cert:\LocalMachine\My\$($Obj.Certificate)"
        }
        else
        {
            Write-Error "The certificate '$($Obj.Certificate)' could not be found or access is denied." -ErrorAction Stop
        }

        if (!$Certificate)
        {
            Write-Error "Failed to retrieve certificate '$($Obj.Certificate)' or access is denied." -ErrorAction Stop
        }

        Write-Verbose "Certificate '$($Certificate.Subject)' with thumbprint '$($Certificate.Thumbprint)' will be used for decryption."

        if (!$Certificate.HasPrivateKey -or $Certificate.PrivateKey -eq $null)
        {
            Write-Error "The certificate '$($Certificate.Subject)' with thumbprint '$($Certificate.Thumbprint)' does not contain a private key or access is denied." -ErrorAction Stop
        }

        $Key = [Convert]::FromBase64String($Obj.Provider.Key)

        $Provider = Invoke-Expression -Command "[$($Obj.Provider.Type)]::Create()"
        $Provider.BlockSize    = $Obj.Provider.BlockSize
        $Provider.FeedbackSize = $Obj.Provider.FeedbackSize
        $Provider.KeySize      = $Obj.Provider.KeySize
        $Provider.Mode         = $Obj.Provider.Mode
        $Provider.Padding      = $Obj.Provider.Padding
        $Provider.Key          = $Certificate.PrivateKey.Decrypt($Key, $true)
        $Provider.IV           = [Convert]::FromBase64String($Obj.Provider.IV)
        
        $Transform  = $Provider.CreateDecryptor()
        $DataStream = New-Object System.IO.MemoryStream (,[Convert]::FromBase64String($Obj.Data))
        $Stream     = New-Object System.Security.Cryptography.CryptoStream ($DataStream, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $Reader     = New-Object System.IO.StreamReader ($Stream, ([System.Text.Encoding]::"$($Obj.Encoding)"))
        
        if ($AsSecureString)
        {
            ConvertTo-SecureString -String $Reader.ReadToEnd() -AsPlainText -Force
        }
        else
        {
            $Reader.ReadToEnd()
        }

        $Reader.Close()
        $Stream.Close()
    }
}
