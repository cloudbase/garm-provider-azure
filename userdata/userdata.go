package userdata

import (
	"bytes"
	"fmt"
	"text/template"
)

var WindowsSetupScriptTemplate = `#ps1_sysnative
Param(
	[Parameter(Mandatory=$false)]
	[string]$Token="{{.CallbackToken}}"
)

$ErrorActionPreference="Stop"

function Invoke-FastWebRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=0)]
        [System.Uri]$Uri,
        [Parameter(Position=1)]
        [string]$OutFile,
        [Hashtable]$Headers=@{},
        [switch]$SkipIntegrityCheck=$false
    )
    PROCESS
    {
        if(!([System.Management.Automation.PSTypeName]'System.Net.Http.HttpClient').Type)
        {
            $assembly = [System.Reflection.Assembly]::LoadWithPartialName("System.Net.Http")
        }

        if(!$OutFile) {
            $OutFile = $Uri.PathAndQuery.Substring($Uri.PathAndQuery.LastIndexOf("/") + 1)
            if(!$OutFile) {
                throw "The ""OutFile"" parameter needs to be specified"
            }
        }

        $fragment = $Uri.Fragment.Trim('#')
        if ($fragment) {
            $details = $fragment.Split("=")
            $algorithm = $details[0]
            $hash = $details[1]
        }

        if (!$SkipIntegrityCheck -and $fragment -and (Test-Path $OutFile)) {
            try {
                return (Test-FileIntegrity -File $OutFile -Algorithm $algorithm -ExpectedHash $hash)
            } catch {
                Remove-Item $OutFile
            }
        }

        $client = new-object System.Net.Http.HttpClient
        foreach ($k in $Headers.Keys){
            $client.DefaultRequestHeaders.Add($k, $Headers[$k])
        }
        $task = $client.GetStreamAsync($Uri)
        $response = $task.Result
        if($task.IsFaulted) {
            $msg = "Request for URL '{0}' is faulted. Task status: {1}." -f @($Uri, $task.Status)
            if($task.Exception) {
                $msg += "Exception details: {0}" -f @($task.Exception)
            }
            Throw $msg
        }
        $outStream = New-Object IO.FileStream $OutFile, Create, Write, None

        try {
            $totRead = 0
            $buffer = New-Object Byte[] 1MB
            while (($read = $response.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $totRead += $read
                $outStream.Write($buffer, 0, $read);
            }
        }
        finally {
            $outStream.Close()
        }
        if(!$SkipIntegrityCheck -and $fragment) {
            Test-FileIntegrity -File $OutFile -Algorithm $algorithm -ExpectedHash $hash
        }
    }
}

function Import-Certificate() {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$CertificatePath,
        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation="LocalMachine",
        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.StoreName]$StoreName="TrustedPublisher"
    )
    PROCESS
    {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            $StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $CertificatePath)
        $store.Add($cert)
    }
}

function Invoke-APICall() {
	[CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [object]$Payload,
		[parameter(Mandatory=$true)]
		[string]$CallbackURL
    )
	PROCESS{
		Invoke-WebRequest -UseBasicParsing -Method Post -Headers @{"Accept"="application/json"; "Authorization"="Bearer $Token"} -Uri $CallbackURL -Body (ConvertTo-Json $Payload) | Out-Null
	}
}

function Update-GarmStatus() {
	[CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$Message,
		[parameter(Mandatory=$true)]
		[string]$CallbackURL
    )
	PROCESS{
		$body = @{
			"status"="installing"
			"message"=$Message
		}
		Invoke-APICall -Payload $body -CallbackURL $CallbackURL | Out-Null
	}
}

function Invoke-GarmSuccess() {
	[CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$Message,
		[parameter(Mandatory=$true)]
        [int64]$AgentID,
		[parameter(Mandatory=$true)]
		[string]$CallbackURL
    )
	PROCESS{
		$body = @{
			"status"="idle"
			"message"=$Message
			"agent_id"=$AgentID
		}
		Invoke-APICall -Payload $body -CallbackURL $CallbackURL | Out-Null
	}
}

function Invoke-GarmFailure() {
	[CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$Message,
		[parameter(Mandatory=$true)]
		[string]$CallbackURL
    )
	PROCESS{
		$body = @{
			"status"="failed"
			"message"=$Message
		}
		Invoke-APICall -Payload $body -CallbackURL $CallbackURL | Out-Null
		Throw $Message
	}
}

$PEMData = @"
{{.CABundle}}
"@

function Install-Runner() {
	$CallbackURL="{{.CallbackURL}}"
	if ($Token.Length -eq 0) {
		Throw "missing callback authentication token"
	}
	try {
		$MetadataURL="{{.MetadataURL}}"
		$DownloadURL="{{.DownloadURL}}"
		if($MetadataURL -eq ""){
			Throw "missing metadata URL"
		}

		if($PEMData.Trim().Length -gt 0){
			Set-Content $env:TMP\garm-ca.pem $PEMData
			Import-Certificate -CertificatePath $env:TMP\garm-ca.pem
		}

		$GithubRegistrationToken = Invoke-WebRequest -UseBasicParsing -Headers @{"Accept"="application/json"; "Authorization"="Bearer $Token"} -Uri $MetadataURL/runner-registration-token/
		Update-GarmStatus -CallbackURL $CallbackURL -Message "downloading tools from $DownloadURL"

		$downloadToken="{{.TempDownloadToken}}"
		$DownloadTokenHeaders=@{}
		if ($downloadToken.Length -gt 0) {
			$DownloadTokenHeaders=@{
				"Authorization"="Bearer $downloadToken"
			}
		}
		$downloadPath = Join-Path $env:TMP {{.FileName}}
		Invoke-FastWebRequest -Uri $DownloadURL -OutFile $downloadPath -Headers $DownloadTokenHeaders

		$runnerDir = "C:\runner"
		mkdir $runnerDir

		Update-GarmStatus -CallbackURL $CallbackURL -Message "extracting runner"
		Add-Type -AssemblyName System.IO.Compression.FileSystem
		[System.IO.Compression.ZipFile]::ExtractToDirectory($downloadPath, "$runnerDir")

		Update-GarmStatus -CallbackURL $CallbackURL -Message "configuring runner and starting runner"
		cd $runnerDir
		./config.cmd --unattended --url "{{ .RepoURL }}" --token $GithubRegistrationToken --name "{{ .RunnerName }}" --labels "{{ .RunnerLabels }}" --ephemeral --runasservice

		$agentInfoFile = Join-Path $runnerDir ".runner"
		$agentInfo = ConvertFrom-Json (gc -raw $agentInfoFile)
		Invoke-GarmSuccess -CallbackURL $CallbackURL -Message "runner successfully installed" -AgentID $agentInfo.agentId
	} catch {
		Invoke-GarmFailure -CallbackURL $CallbackURL -Message $_
	}
}
Install-Runner
`

var WindowsRunScriptTemplate = "try { gc -Raw C:/AzureData/CustomData.bin | sc /run.ps1; /run.ps1 -Token \"{{.CallbackToken}}\" } finally { rm -Force -ErrorAction SilentlyContinue /run.ps1 }"

type InstallRunnerParams struct {
	FileName          string
	DownloadURL       string
	RepoURL           string
	MetadataURL       string
	RunnerName        string
	RunnerLabels      string
	CallbackURL       string
	TempDownloadToken string
	CABundle          string
	CallbackToken     string
}

func GetWindowsInstallRunnerScript(params InstallRunnerParams) ([]byte, error) {
	t, err := template.New("").Parse(WindowsSetupScriptTemplate)
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("error rendering template: %w", err)
	}

	return buf.Bytes(), nil
}

func GetWindowsRunScriptCommand(callbackToken string) ([]byte, error) {
	t, err := template.New("").Parse(WindowsRunScriptTemplate)
	if err != nil {
		return nil, fmt.Errorf("error parsing template: %w", err)
	}

	params := struct {
		CallbackToken string
	}{
		CallbackToken: callbackToken,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("error rendering template: %w", err)
	}

	return buf.Bytes(), nil
}
