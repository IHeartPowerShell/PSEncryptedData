function Import-PSEncryptedCredential
{
    [OutputType([PSCredential])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    process
    {
        Import-PSEncryptedData -Path $Path | ConvertFrom-Json | ForEach-Object {New-Object PSCredential $_.UserName,(ConvertTo-SecureString -String $_.Password -AsPlainText -Force)}
    }
}