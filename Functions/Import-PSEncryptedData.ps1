function Import-PSEncryptedData
{
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [ValidateSet('ASCII','BigEndianUnicode','Unicode','UTF7','UTF8','UTF32')]
        [string] $Encoding = 'Default',

        [switch] $AsSecureString = $false
    )

    process
    {
        Get-Content -Path $Path -Encoding $Encoding | Out-String | ConvertFrom-PSEncryptedData -AsSecureString:$AsSecureString
    }
}