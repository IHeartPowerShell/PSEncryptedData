function New-PSEncryptedDataCertificate
{
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter()]
        [ValidateSet('CurrentUser','LocalMachine')]
        [string] $CertStore = 'CurrentUser'
    )

    try
    {
        $Subject = New-Object -ComObject X509Enrollment.CX500DistinguishedName.1
        $Subject.Encode("CN=$($Name),CN=$($env:COMPUTERNAME),CN=PSEncryptedData", 0)

        $Key = New-Object -ComObject X509Enrollment.CX509PrivateKey.1 -Property @{
                    ProviderName       = 'Microsoft RSA SChannel Cryptographic Provider'
                    KeySpec            = 1
                    Length             = 2048
                    SecurityDescriptor = 'D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)'
                    MachineContext     = if($CertStore -eq 'CurrentUser'){0}else{1}
                    ExportPolicy       = 0
                }
    
        $Key.Create()

        $OIDs = New-Object -ComObject X509Enrollment.CObjectIds.1
    
        $ServerAuthOID = New-Object -ComObject X509Enrollment.CObjectId.1
        $ServerAuthOID.InitializeFromValue('1.3.6.1.5.5.7.3.1')
        $OIDS.Add($ServerAuthOID)

        $Extensions = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage.1
        $Extensions.InitializeEncode($OIDs)

        $CSR = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate.1 
    
        if ($CertStore -eq 'CurrentUser')
        {
            $CSR.InitializeFromPrivateKey(1, $Key, '')
        }
        else
        {
            $CSR.InitializeFromPrivateKey(2, $Key, '')
        }

        $CSR.Subject   = $Subject
        $CSR.Issuer    = $CSR.Subject
        $CSR.NotBefore = ((Get-Date) - (New-TimeSpan -Minutes 5))
        $CSR.NotAfter  = ((Get-Date) + (New-TimeSpan -Days 730))

        $CSR.X509Extensions.Add($Extensions)
        $CSR.Encode()

        $Enrollment = New-Object -ComObject X509Enrollment.CX509Enrollment.1
        $Enrollment.InitializeFromRequest($CSR)

        $CSRResponse = $Enrollment.CreateRequest(0)

        $Enrollment.InstallResponse(2, $CSRResponse, 0, '')

        Get-ChildItem "Cert:\$($CertStore)\My" | Where-Object Subject -eq $Subject.Name
    }
    catch
    {
        throw
    }
}