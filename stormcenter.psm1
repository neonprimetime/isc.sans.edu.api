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
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message)"
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
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message)"
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
        [string[]]$Date,

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
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message)"
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
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message)"
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
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message)"
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
        Get-ISCPort 80 "2017-06-21"
        
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
        [string[]]$Date
    )
    Begin {
    }
    Process {
        $url = "https://isc.sans.edu/api/portdate/{0}/{1}" -f $Port, $Date
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message)"
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
        Get-ISCTopPorts 2017-06-21 10
        
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
        [string[]]$Date,

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
        $url = "https://isc.sans.edu/api/topports/records/{0}/{1}" -f $RowCount, $Date
        try{
            [xml]$xmlresults = (wget $url).Content
        }catch{
            Write-Warning -Message "Failed to connect to API because $($_.Exception.Message)"
        }
        return $xmlresults.topports.port | Format-Table
    }
    End {}
}