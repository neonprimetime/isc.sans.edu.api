Function Get-ISCInfocon {
<#
    .SYNOPSIS
        Get infoscon status
    .DESCRIPTION
        Use the ISC SANS API to get infocon status
    .EXAMPLE
        Get-ISCInfocon
        
#>
    Begin {
    }
    Process {
        try{
            [xml]$xmlresults = (wget https://isc.sans.edu/api/infocon).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        $infocon = $xmlresults.infocon.status
        return $infocon
    }
    End {}
}
Function Get-ISCHandler {
<#
    .SYNOPSIS
        Get ISC handler on duty
    .DESCRIPTION
        Use the ISC SANS API to get handler on duty
    .EXAMPLE
        Get-ISCHandler
        
#>
    Begin {
    }
    Process {
        try{
            [xml]$xmlresults = (wget https://isc.sans.edu/api/handler).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        $handler = $xmlresults.handler.name
        return $handler
    }
    End {}
}
Function Get-ISCBackscatter {
<#
    .SYNOPSIS
        Get backscatter data
    .DESCRIPTION
        Use the ISC SANS API to get backscatter data
    .EXAMPLE
        Get-ISCBackscatter 2017-06-21 10
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$RowCount
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/backscatter/{0}/{1}" -f $Date, $RowCount
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.backscatter.sourceport | Format-Table
    }
    End {}
}
Function Get-ISCIp {
<#
    .SYNOPSIS
        Get ip address data
    .DESCRIPTION
        Use the ISC SANS API to get ip address data
    .EXAMPLE
        Get-ISCIp 70.91.145.10
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                If ([bool]($_ -as [ipaddress])) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string[]]$IpAddress
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/ip/{0}" -f $IpAddress
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        $table = @{}
        $xmlresults.ip.ChildNodes | Foreach {if($_.Name -eq "asname") { $table["asname"] = [regex]::match($_.InnerXml,'\<\!\[CDATA\[([^\]]+)\]').Groups[1].Value} elseif($_.Name -eq "threatfeeds") { $counter = 1; Foreach($threatfeed in $_.ChildNodes) { $table["threatfeed$counter"] = $threatfeed.Name + "(First:{0}, Last:{1})" -f $threatfeed["firstseen"].InnerXml,$threatfeed["lastseen"].InnerXml ; $counter++ } $table["threatfeedcount"] = $counter-1} else {$table[$_.Name] = $_.InnerXml}}
        return $table.GetEnumerator() | sort -Property Name
    }
    End {}
}
Function Get-ISCPort {
<#
    .SYNOPSIS
        Get port data
    .DESCRIPTION
        Use the ISC SANS API to get port data
    .EXAMPLE
        Get-ISCPort 80
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$Port
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/port/{0}" -f $Port
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        $table = @{}
        $xmlresults.port.ChildNodes | Foreach {if($_.Name -eq "services") { $counter = 1; Foreach($service in $_.ChildNodes) { $table["service$counter"] = $service.Name + "(Service:{0}, Name:{1})" -f $service["service"].InnerXml,$service["name"].InnerXml ; $counter++ } $table["servicecount"] = $counter-1} elseif($_.Name -eq "data") { Foreach($data in $_.ChildNodes) { $table[$data.Name] = $data.InnerXml ; } } else {$table[$_.Name] = $_.InnerXml}}
        return $table
    }
    End {}
}
Function Get-ISCPortDate {
<#
    .SYNOPSIS
        Get port data by date
    .DESCRIPTION
        Use the ISC SANS API to get port data by date
    .EXAMPLE
        Get-ISCPort 80 2017-06-21
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$Port,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date
    )
    Begin {
    }
    Process {
        if($SortBy -eq "") { $SortBy = "portdate" }
        $url = "https://isc.sans.edu/api/portdate/{0}/{1}" -f $Port, $Date
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        $table = @{}
        $xmlresults.portdate.ChildNodes | Foreach {if($_.Name -eq "data") { Foreach($data in $_.ChildNodes) { $table[$data.Name] = $data.InnerXml ; } } else {$table[$_.Name] = $_.InnerXml}}
        return $table
    }
    End {}
}
Function Get-ISCTopPorts {
<#
    .SYNOPSIS
        Get top ports
    .DESCRIPTION
        Use the ISC SANS API to get top ports
    .EXAMPLE
        Get-ISCTopPorts 2017-06-21 10 records
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$RowCount,
        
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$SortBy
    )
    Begin {
    }
    Process {
        if($SortBy -eq "") { $SortBy = "records" }
        $url = "https://isc.sans.edu/api/topports/{2}/{0}/{1}" -f $RowCount, $Date, $SortBy
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.topports.port | Format-Table
    }
    End {}
}
Function Get-ISCTopIps {
<#
    .SYNOPSIS
        Get top IP addresses
    .DESCRIPTION
        Use the ISC SANS API to get top IP Addresses
    .EXAMPLE
        Get-ISCTopIps 2017-06-21 10 records
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$RowCount,
        
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$SortBy
    )
    Begin {
    }
    Process {
        if($SortBy -eq "") { $SortBy = "records" }
        $url = "https://isc.sans.edu/api/topips/{2}/{0}/{1}" -f $RowCount, $Date, $SortBy
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.topips.ipaddress | Format-Table
    }
    End {}
}
Function Get-ISCSources {
<#
    .SYNOPSIS
        Get top Source ip addresses last 30 days
    .DESCRIPTION
        Use the ISC SANS API to get source IP Addresses last 30 days
    .EXAMPLE
        Get-ISCSources 2017-06-21 10 attacks
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$RowCount,
        
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$SortBy
    )
    Begin {
    }
    Process {
        if($SortBy -eq "") { $SortBy = "attacks" }
        $url = "https://isc.sans.edu/api/sources/{2}/{0}/{1}" -f $RowCount, $Date, $SortBy
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.sources.data | Format-Table
    }
    End {}
}
Function Get-ISCPortHistory {
<#
    .SYNOPSIS
        Get port history by date range
    .DESCRIPTION
        Use the ISC SANS API to get port history by date range
    .EXAMPLE
        Get-ISCPortHistory 80 2017-06-20 2017-06-21
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$Port,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$StartDate,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$EndDate
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/porthistory/{0}/{1}/{2}" -f $Port, $StartDate, $EndDate
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.porthistory.portinfo | Format-Table
    }
    End {}
}
Function Get-ISCAsnum {
<#
    .SYNOPSIS
        Get AS information
    .DESCRIPTION
        Use the ISC SANS API to get the AS information
    .EXAMPLE
        Get-ISCAsnum 4837 10
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$Asnum,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$RowCount
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/asnum/{0}/{1}" -f $RowCount, $Asnum
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.asnum.data | Format-Table
    }
    End {}
}
Function Get-ISCDailySummary {
<#
    .SYNOPSIS
        Get daily summary by date range
    .DESCRIPTION
        Use the ISC SANS API to get daily summary by date range
    .EXAMPLE
        Get-ISCDailySummary 2017-06-20 2017-06-21
        
#>
    Param(        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$StartDate,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$EndDate
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/dailysummary/{0}/{1}" -f $StartDate, $EndDate
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.dailysummary.daily | Format-Table
    }
    End {}
}
Function Get-ISCDaily404Summary {
<#
    .SYNOPSIS
        Get daily 404 project summary by date range
    .DESCRIPTION
        Use the ISC SANS API to get daily 404 project summary by date range
    .EXAMPLE
        Get-ISCDaily404Summary 2017-06-19 2017-06-21
        
#>
    Param(        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$StartDate,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$EndDate
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/daily404summary/{0}/{1}" -f $StartDate, $EndDate
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.daily404summary.Daily404Data | Format-Table
    }
    End {}
}
Function Get-ISCDaily404Detail {
<#
    .SYNOPSIS
        Get daily 404 project details
    .DESCRIPTION
        Use the ISC SANS API to get daily 404 project details
    .EXAMPLE
        Get-ISCDaily404Detail 2017-06-21 10
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$RowCount
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/daily404detail/{0}/{1}" -f $Date, $RowCount
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.daily404detail.data | % { $ua = [regex]::match($_.user_agent.InnerXml,'\<\!\[CDATA\[([^\]]+)\]').Groups[1].Value; $_.user_agent.InnerText = $ua; $_ } | Format-Table
    }
    End {}
}
Function Get-ISCGlossary {
<#
    .SYNOPSIS
        Get the glossary
    .DESCRIPTION
        Use the ISC SANS API to get the glossary
    .EXAMPLE
        Get-ISCGlossary
        
#>
    Param(
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/glossary"
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.glossary.item | Format-Table
    }
    End {}
}
Function Get-ISCThreatFeeds {
<#
    .SYNOPSIS
        Get the Threat Feeds
    .DESCRIPTION
        Use the ISC SANS API to get the threat feeds
    .EXAMPLE
        Get-ISCThreatFeeds
        
#>
    Param(
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/threatfeeds/"
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.threatfeeds.threatfeed | % { try { $name = [regex]::match($_.name.InnerXml,'\<\!\[CDATA\[([^\]]+)\]').Groups[1].Value; $_.name.InnerText = $name; } catch {} ; try { $description = [regex]::match($_.description.InnerXml,'\<\!\[CDATA\[([^\]]+)\]').Groups[1].Value; $_.description.InnerText = $description; } catch {}; $_ } | Format-Table
    }
    End {}
}
Function Get-ISCThreatFeedsPerDay {
<#
    .SYNOPSIS
        Get Threat Feeds per day
    .DESCRIPTION
        Use the ISC SANS API to get Threat Feeds per day
    .EXAMPLE
        Get-ISCThreatFeedsPerDay 2017-06-19 2017-06-21
        
#>
    Param(        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$StartDate,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$EndDate
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/threatfeeds/perday/{0}/{1}" -f $StartDate, $EndDate
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.threatfeeds.day | Format-Table
    }
    End {}
}
Function Get-ISCThreatFeedsByDataFeed {
<#
    .SYNOPSIS
        Get Threat Feeds per day by data feed
    .DESCRIPTION
        Use the ISC SANS API to get Threat Feeds per day by data feed
    .EXAMPLE
        Get-ISCThreatFeedsByDataFeed 2017-06-19 2017-06-24 blocklistde110
        
#>
    Param(        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$StartDate,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$EndDate,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$DataFeed
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/threatfeeds/feedperday/{0}/{1}/{2}" -f $StartDate, $EndDate, $DataFeed
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.threatfeeds.feedday | Format-Table
    }
    End {}
}
Function Get-ISCThreatFeedIps {
<#
    .SYNOPSIS
        Get Threat feed ips per day by data feed
    .DESCRIPTION
        Use the ISC SANS API to get Threat feed ips per day by data feed
    .EXAMPLE
        Get-ISCThreatFeedIps 2017-06-19 2017-06-24 blocklistde110
        
#>
    Param(        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$StartDate,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$EndDate,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$DataFeed
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/threatlist/{2}/{0}/{1}" -f $StartDate, $EndDate, $DataFeed
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.threatlist.ChildNodes | Format-Table
    }
    End {}
}
Function Get-ISCThreatFeedByCategory {
<#
    .SYNOPSIS
        Get Threat feed ips per day by category
    .DESCRIPTION
        Use the ISC SANS API to get Threat feed ips per day by category
    .EXAMPLE
        Get-ISCThreatFeedByCategory 2017-06-19 2017-06-24 bots
        
#>
    Param(        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$StartDate,
        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$EndDate,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$Category
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/threatcategory/{2}/{0}/{1}" -f $StartDate, $EndDate, $Category
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.threatcategory.ChildNodes | Format-Table
    }
    End {}
}
Function Get-ISCWebHoneypotSummary {
<#
    .SYNOPSIS
        Get web honeypot summary
    .DESCRIPTION
        Use the ISC SANS API to get web honeypot summary
    .EXAMPLE
        Get-ISCWebHoneypotSummary 2017-06-19
        
#>
    Param(        
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/webhoneypotsummary/{0}" -f $Date
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.webhoneypotsummary | Format-Table
    }
    End {}
}
Function Get-ISCWebHoneypotByType {
<#
    .SYNOPSIS
        Get web honeypot by type
    .DESCRIPTION
        Use the ISC SANS API to get web honeypot by type
    .EXAMPLE
        Get-ISCWebHoneypotByType
        
#>
    Param(
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/webhoneypotbytype" -f $Date
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }
        return $xmlresults.webhoneypotbytype.item | Format-Table
    }
    End {}
}
Function Get-ISCOpenIOCLogs {
<#
    .SYNOPSIS
        Get firewall logs in OpenIOC format
    .DESCRIPTION
        Use the ISC SANS API to get firewall logs in OpenIOC format, returns raw xml
    .EXAMPLE
        Get-ISCOpenIOCLogs 2017-06-21 10
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$RowCount,

        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if($_ -eq "0"){
                    $true
                }elseif(([System.Int32]::Parse($_))) {
                    $intval = [System.Int32]::Parse($_)
                    if($intval -lt 1){
                        $false
                    }else{
                        $true
                    }
                }
            } catch {
                $false
            }
        })]
        [int]$PageNumber
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/openiocsources/{0}/{1}/{2}" -f $Date, $RowCount, $PageNumber
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }        
        $StringWriter = New-Object System.IO.StringWriter 
        $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
        $xmlWriter.Formatting = “indented” 
        $xmlWriter.Indentation = $Indent 
        $xmlresults.WriteContentTo($XmlWriter) 
        $XmlWriter.Flush() 
        $StringWriter.Flush() 
        return $StringWriter.ToString() 
    }
    End {}
}
Function Get-ISCMSPatchDay {
<#
    .SYNOPSIS
        Get Microsoft Patch day details, *NOTICE* deprecated as its no longer updated
    .DESCRIPTION
        Use the ISC SANS API to get microsoft patch day details
    .EXAMPLE
        Get-ISCMSPatchDay 2017-06-21
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            try {
                if(([System.DateTime]::ParseExact($_,"yyyy-MM-dd",[System.Globalization.CultureInfo]::InvariantCulture))) {
                    $true
                }
            } catch {
                $false
            }
        })]
        [string]$Date
    )
    Begin {
    }
    Process {
        Write-Warning -Message "*NOTICE* deprecated"
        $url = "https://isc.sans.edu/api/getmspatchday/{0}" -f $Date
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }        
        $StringWriter = New-Object System.IO.StringWriter 
        $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
        $xmlWriter.Formatting = “indented” 
        $xmlWriter.Indentation = $Indent 
        $xmlresults.WriteContentTo($XmlWriter) 
        $XmlWriter.Flush() 
        $StringWriter.Flush() 
        return $StringWriter.ToString() 
    }
    End {}
}
Function Get-ISCMSPatch {
<#
    .SYNOPSIS
        Get specific Microsoft Patch detail
    .DESCRIPTION
        Use the ISC SANS API to get specific microsoft patch detail
    .EXAMPLE
        Get-ISCMSPatch MS16-023
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$Patch
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/getmspatch/{0}" -f $Patch
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }        
        return $xmlresults.getmspatch | % { try { $_.affected.InnerText = [regex]::match($_.affected.InnerXml,'\<\!\[CDATA\[([^\]]+)\]').Groups[1].Value; } catch {} ; $_; } | Format-Table
    }
    End {}
}
Function Get-ISCMSPatchCVEs {
<#
    .SYNOPSIS
        Get specific Microsoft Patch CVEs
    .DESCRIPTION
        Use the ISC SANS API to get specific microsoft patch CVEs
    .EXAMPLE
        Get-ISCMSPatchCVEs MS16-023
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$Patch
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/getmspatchcves/{0}" -f $Patch
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }        
        return $xmlresults.getmspatchcves.getmspatchcves | Format-Table
    }
    End {}
}
Function Get-ISCMSPatchKBs {
<#
    .SYNOPSIS
        Get specific Microsoft Patch KBs
    .DESCRIPTION
        Use the ISC SANS API to get specific microsoft patch KBs
    .EXAMPLE
        Get-ISCMSPatchKBs MS16-023
        
#>
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [ValidateScript({
            $true
        })]
        [string]$Patch
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/getmspatchreplaces/{0}" -f $Patch
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message) $($url)"
        }        
        return $xmlresults.getmspatchreplaces.getmspatchreplaces | Format-Table
    }
    End {}
}