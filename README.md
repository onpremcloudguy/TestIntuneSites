# welcome to the Readme #

This script allows the ability to check that the ports are open, and validates that the certificates are issued by Microsoft

You need to have installed Pester on your computer before running the script using **Install-Module -Name Pester -Force**

to execute run invoke-pester .\test-intunesites.ps1 from powershell

Thanks to Anoop for the list of Sites: <https://www.anoopcnair.com/windows-10-proxy-requirements-for-intune/?fbclid=IwAR3uB-2hF1pIcWzUQ9a7byzbNbiLjpj2IKZyTrqld4RvHx_Qo5PBYCPOs1Q>

and Chris Duck for the test-sslprotocol function: <http://blog.whatsupduck.net/2014/10/checking-ssl-and-tls-versions-with-powershell.html>

* TODO: add more sites
* TODO: Find a solution for WildCard Sites
* TODO: Handle Certs which are using akimai rather then Microsoft (not always presenting thecert to PowerShell)
