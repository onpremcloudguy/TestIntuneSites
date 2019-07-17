$scriptpath = $PSScriptRoot
$jsonpath = "$scriptpath\intunesites.json"
<#
    .DESCRIPTION
    Outputs the SSL protocols that the client is able to successfully use to connect to a server.

    .PARAMETER ComputerName
    The name of the remote computer to connect to.

    .PARAMETER Port
    The remote port to connect to. The default is 443.

    .EXAMPLE
    Test-SslProtocol -ComputerName "www.google.com"

    ComputerName       : www.google.com
    Port               : 443
    KeyLength          : 2048
    SignatureAlgorithm : rsa-sha1
    Ssl2               : False
    Ssl3               : True
    Tls                : True
    Tls11              : True
    Tls12              : True

    .NOTES
    Copyright 2014 Chris Duck
    http://blog.whatsupduck.net

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
#>
function Test-SslProtocol {
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        $ComputerName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [int]$Port = 443
    )
    begin {
        $ProtocolNames = [System.Security.Authentication.SslProtocols] |
        Get-Member -Static -MemberType Property |
        Where-Object -Filter { $_.Name -notin @("Default", "None") } |
        Foreach-Object { $_.Name }
    }
    process {
        $ProtocolStatus = [Ordered]@{ }
        $ProtocolStatus.Add("ComputerName", $ComputerName)
        $ProtocolStatus.Add("Port", $Port)
        $ProtocolStatus.Add("KeyLength", $null)
        $ProtocolStatus.Add("SignatureAlgorithm", $null)

        $ProtocolNames | foreach-object {
            $ProtocolName = $_
            $Socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
            $Socket.Connect($ComputerName, $Port)
            try {
                $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
                $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true)
                $SslStream.AuthenticateAsClient($ComputerName, $null, $ProtocolName, $false )
                $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
                $ProtocolStatus["KeyLength"] = $RemoteCertificate.PublicKey.Key.KeySize
                $ProtocolStatus["SignatureAlgorithm"] = $RemoteCertificate.SignatureAlgorithm.FriendlyName
                $ProtocolStatus["Certificate"] = $RemoteCertificate
                $ProtocolStatus.Add($ProtocolName, $true)
            }
            catch {
                $ProtocolStatus.Add($ProtocolName, $false)
            }
            finally {
                $SslStream.Close()
            }
        }
        [PSCustomObject]$ProtocolStatus
    }
} 

$sites = get-content $jsonpath | ConvertFrom-Json
foreach ($site in $sites.sites) {
    $wildsite = $false
    if ($site.https -eq 'True') { $port = 443 }else { $port = 80 }
    Describe "$($site.site) on port: $port for the $($site.relation) service" {
        if ($site.site.Contains('*')) { $wildsite = $true }
        it 'Domain name does not include a *' { $site.site.Contains('*') | should be $false }
        $res = Test-NetConnection $site.site -Port $port -WarningAction SilentlyContinue
        if (!($wildsite)) {
            it "Response on $port" { $res.TcpTestSucceeded | should be $true }
            if ($res.TcpTestSucceeded -and $port -eq 443) {
                $cert = Test-SslProtocol $site.site
                it 'Certificate is issued by Microsoft' { $cert.Certificate.Issuer.Contains("Microsoft") | should be $true }
            }
        }
    }
}
