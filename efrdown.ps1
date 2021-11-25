

# bring your own API keys
$TH_KEY = "bring your own API keys"
$TH_SECRET = "and secrets"

$EP_KEY = "bring your own API keys"
$EP_SECRET = "and secrets"
function New-CpPortalSession ($key, $secret) {
    $body = @{
        clientId  = $key;
        accessKey = $secret
    } | ConvertTo-Json
    $res = Invoke-RestMethod -Uri "https://cloudinfra-gw.portal.checkpoint.com/auth/external" `
        -Headers @{"Content-Type" = "application/json" } `
        -Body $body -Method Post
    $Script:cpPortalToken = $res.data.token
    $Script:cpPortalToken
}

function New-CpEpmSession {
    $url = "https://cloudinfra-gw.portal.checkpoint.com/app/endpoint-web-mgmt/webmgmt/graphql" 
    $portalToken = $Script:cpPortalToken
    $headers = @{ 
        "Content-Type"  = "application/json";
        "Authorization" = "Bearer ${portalToken}"
    }
    $query = @'
    query Login {
        loginExternal {
          token
          apiVersion
          isReadOnly
          frontVersion
          serverVersionInfo {
            majorVersion
            takeNumber
            hotFixVersions
            __typename
          }
          __typename
        }
      }
'@

    $vars = @{}

    $body = @{
        query     = $query;
        variables = $vars
    } | ConvertTo-Json -Depth 10

    $res = Invoke-RestMethod -Uri $url `
        -Method Post `
        -Headers $headers `
        -Body $body 

    $Script:cpEpmToken = $res.data.loginExternal.token
    $Script:cpEpmToken
}

function Get-CpThIncident {
    $url = "https://cloudinfra-gw.portal.checkpoint.com/app/threathunting/prod-gcp-apollo/" 
    $portalToken = $Script:cpPortalToken
    
    $headers = @{
        'Content-Type'  = 'application/json';
        'Authorization' = "Bearer $portalToken"
    }

    $variablesTemplate = @"
    {
        "indicators": [
          {
            "fieldArr": "",
            "fieldType": "DetectionAttackStatus",
            "operator": "Exists",
            "escaped": true
          }
        ],
        "queryParam": {
          "dateRange": {
            "from": "2021-11-23T23:00:00Z",
            "to": "2021-11-24T22:59:59.999Z"
          },
          "pagination": {
            "maxResults": 50,
            "pageToken": null
          },
          "aggregations": {
            "selectDistinct": false
          },
          "jobId": null,
          "useRepCache": false,
          "orderBy": {
            "field": "OpTimeUTC",
            "ascDesc": "DESC"
          },
          "recordTypes": [
            "DetectionEvent"
          ],
          "dataSourceTypes": [
            "endpoint"
          ]
        },
        "includeRecordBase": true,
        "includeRecordProcess": false,
        "includeRecordFile": false,
        "includeRecordEmail": false,
        "includeRecordNetwork": false,
        "includeRecordRegistry": false,
        "includeRecordInject": false,
        "includeRecordRemoteLogon": false,
        "includeRecordScript": false,
        "includeDetectionEvent": true,
        "includeAdvancedActivity": false,
        "includeIndirectExecution": false,
        "includeRemoteExecution": false,
        "includeMTA": false,
        "includeGWStats": false,
        "includeLAAS": false,
        "includeMitre": true,
        "includeShadowIT": true
      }
"@
    $variables = $variablesTemplate | ConvertFrom-Json
    $fromTsStr = ((Get-Date).AddDays(-7)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK")
    $toTsStr = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffK")
    $variables.queryParam.dateRange.from = $fromTsStr
    $variables.queryParam.dateRange.to = $toTsStr

    $query = '
query searchRecords($indicators: [Indicator]!, $queryParam: QueryParam, $includeRecordBase: Boolean!, $includeRecordProcess: Boolean!, $includeRecordFile: Boolean!, $includeRecordNetwork: Boolean!, $includeRecordRegistry: Boolean!, $includeRecordInject: Boolean!, $includeRecordEmail: Boolean!, $includeRecordRemoteLogon: Boolean!, $includeRecordScript: Boolean!, $includeDetectionEvent: Boolean!, $includeMitre: Boolean!, $includeShadowIT: Boolean!, $includeAdvancedActivity: Boolean!, $includeIndirectExecution: Boolean!, $includeRemoteExecution: Boolean!, $includeGWStats: Boolean!, $includeMTA: Boolean!, $includeLAAS: Boolean!) {
  searchRecords(indicators: $indicators, queryParam: $queryParam) {
    pagination {
      maxResults
      pageToken
      __typename
    }
    metadata {
      totalRows
      jobId
      __typename
    }
    records {
      ... on EPRecord {
        DataSource
        UUID
        MachineName
        UserName
        OSName
        HostType
        OSVersion
        ProductVersion
        DomainName
        EPGUID
        HostIps
        HostMacs
        Base @include(if: $includeRecordBase) {
          RecordType
          Pid
          CreationTime
          PidCreationTime
          OpTimeUTC
          ProcessArgs
          ProcessDir
          ProcessName
          ProcessPath
          ProcessMD5
          ProcessSigner
          ProcessClassification
          ParentProcessDir
          ProcessTerminationTime
          ParentProcessName
          ParentProcessMD5
          ParentProcessSigner
          ParentProcessClassification
          LogSource
          Browser
          BrowserVersion
          ProcessReputationInfo {
            ReputationType
            Resource
            ProcessClassification
            ProcessRepPositives
            ProcessRepTotal
            ProcessRepRisk
            ProcessRepConfidence
            ProcessRepSeverity
            ProcessRepMalwareFamily
            ProcessRepMalwareTypes
            ProcessRepProtectionName
            VTLink
            __typename
          }
          ParentProcessReputationInfo {
            ReputationType
            Resource
            ProcessClassification
            ProcessRepPositives
            ProcessRepTotal
            ProcessRepRisk
            ProcessRepConfidence
            ProcessRepSeverity
            ProcessRepMalwareFamily
            ProcessRepMalwareTypes
            ProcessRepProtectionName
            VTLink
            __typename
          }
          __typename
        }
        Process @include(if: $includeRecordProcess) {
          ProcessInvalidSigner
          ProcessPPid
          ProcessPCreationTime
          ProcessPPidCreationTime
          ProcessOp
          ProcessIntegrityLevel
          ProcessAccount
          ProcessLogonSession
          ParentProcessIntegrityLevel
          ParentProcessArgs
          ProcessTrustedSigner
          ProcessOriginalName
          __typename
        }
        Email @include(if: $includeRecordEmail) {
          EmailFrom
          EmailTo
          EmailType
          EmailSubject
          EmailServerName
          EmailMessageId
          EmailCC
          EmailBCC
          EmailAttachments
          EmailURLs
          __typename
        }
        File @include(if: $includeRecordFile) {
          FileDir
          FileName
          FileMD5
          FileSize
          FileType
          FileNewDir
          FileNewFileName
          FileOpMask
          FileOp
          FileContent
          FilePath
          FileSigner
          EmailFrom
          EmailTo
          EmailType
          EmailSubject
          EmailServerName
          EmailMessageId
          EmailCC
          EmailBCC
          OriginalFileClassification
          FileReputationInfo {
            ReputationType
            Resource
            FileClassification
            FileRepPositives
            FileRepTotal
            FileRepRisk
            FileRepConfidence
            FileRepSeverity
            FileRepMalwareFamily
            FileRepMalwareTypes
            FileRepProtectionName
            VTLink
            __typename
          }
          __typename
        }
        Network @include(if: $includeRecordNetwork) {
          NetworkProtocol
          NetworkDomain
          NetworkHttpMethod
          NetworkReferer
          NetworkUserAgent
          NetworkResponseStatusCode
          NetworkSrcIP
          NetworkSrcPort
          NetworkDestIP
          NetworkDestPort
          NetworkIsListen
          NetworkURL
          NetworkDisplayedUrl
          NetworkBytesSent
          NetworkBytesReceived
          NetworkType
          NetworkConnectionDirection
          FileName
          FileMD5
          EmailFrom
          EmailTo
          EmailType
          EmailSubject
          EmailServerName
          EmailMessageId
          EmailCC
          EmailBCC
          NetworkIsIframe
          URLReputationInfo {
            ReputationType
            Resource
            URLClassification
            URLRepTotal
            URLRepPositives
            URLRepRisk
            URLRepConfidence
            URLRepSeverity
            URLRepMalwareFamily
            URLRepProtectionName
            URLRepRegistrant
            VTLink
            __typename
          }
          DomainReputationInfo {
            ReputationType
            Resource
            DomainClassification
            DomainRepTotal
            DomainRepPositives
            DomainRepRisk
            DomainRepConfidence
            DomainRepSeverity
            DomainRepMalwareFamily
            DomainRepProtectionName
            DomainRepRegistrant
            VTLink
            __typename
          }
          DestIPReputationInfo {
            ReputationType
            Resource
            IPClassification
            IPRepTotal
            IPRepPositives
            IPRepRisk
            IPRepConfidence
            IPRepSeverity
            IPRepMalwareFamily
            IPRepGeoLocation
            VTLink
            __typename
          }
          NetworkIsRemoteIpConnection
          __typename
        }
        Registry @include(if: $includeRecordRegistry) {
          RegistryKey
          RegistryValue
          RegistryNewData
          RegistryOldData
          RegistryOpMask
          RegistryOp
          __typename
        }
        Inject @include(if: $includeRecordInject) {
          InjectDstPid
          InjectDstCreationTime
          InjectClassification
          InjectDstDir
          InjectDstName
          InjectHookOperation
          __typename
        }
        Script @include(if: $includeRecordScript) {
          ScriptData
          __typename
        }
        RemoteLogon @include(if: $includeRecordRemoteLogon) {
          RemoteAttackerMachineName
          RemoteOwnerUserName
          RemoteOwnerDomainName
          RemoteAttackerIpAddress
          RemoteIpPort
          RemoteLogonType
          EventType
          RemoteEventID
          RemoteEventDescription
          RemoteStatusDescription
          RemoteSubStatusDescription
          RemoteNumberOfConnections
          LogonId
          LinkedLogonId
          UserSID
          LogonOrigin
          LogonAccountType
          __typename
        }
        DetectionEvent @include(if: $includeDetectionEvent) {
          DetectionIncidentId
          DetectionAttackStatus
          DetectionEnforcementMode
          DetectionMalwareAction
          DetectionTriggeredBy
          DetectionThirdPartyVendorName
          DetectionMalwareFamily
          DetectionProtectionName
          DetectionProtectionType
          DetectionIncidentConfidence
          DetectionIncidentSeverity
          DetectionAttackTriggerProc
          DetectionMaliciousPath
          DetectionMaliciousFileDir
          DetectionMaliciousFileName
          DetectionMaliciousDomainName
          DetectionTriggerMD5
          DetectionEntryPointProc
          DetectionAttackRoot
          DetectionCreatingProcDir
          DetectionCreatingProcName
          DetectionCreatingProcMD5
          DetectionCreatingProcSigner
          DetectionCreatingProcPid
          DetectionCreatingProcCreationTime
          DetectionPolicyAutoRemidiation
          DetectionGeneralInfo
          DetectionDescription
          DetectionRemediationPolicy
          DetectionFirstEPNet
          DetectionFirstEPURLReferrer
          DetectionFirstEPFileName
          DetectionFirstEPFileHash
          DetectionAttackUserDomain
          DetectionAttackUserName
          DetectionImpersonatedDomain
          DetectionImpersonatedType
          DetectionImpersonatedBrand
          DetectionEmailMsgID
          DetectionEmailSubject
          DetectionEmailFrom
          DetectionEmailTo
          DetectionEmailAttachmentName
          DetectionEmailEmbeddedURL
          DetectionEmailDateOfDelivery
          __typename
        }
        AdvancedActivity @include(if: $includeAdvancedActivity) {
          ActivityType
          ActivityName
          ActivityDetails
          ActivityTargetProcessDir
          ActivityTargetProcessName
          ActivityTargetProcessArgs
          ActivityTargetPid
          ActivityTargetCreationTime
          __typename
        }
        IndirectExecution @include(if: $includeIndirectExecution) {
          ExecutionType
          ExecutionName
          ExecutionDetails
          ExecutionTargetProcessDir
          ExecutionTargetProcessName
          ExecutionTargetProcessArgs
          ExecutionTargetPid
          ExecutionTargetCreationTime
          ExecutionRemoteSourceMachine
          ExecutionRemoteTargetUserName
          ExecutionRemoteTargetUserDomain
          __typename
        }
        RemoteExecution @include(if: $includeRemoteExecution) {
          RemoteExecutionSourceIpAddress
          RemoteExecutionSourcePort
          RemoteExecutionSourceMachineName
          RemoteExecutionDestinationIpAddress
          RemoteExecutionDestinationPort
          RemoteExecutionUserName
          RemoteExecutionDomainName
          RemoteExecutionUserSID
          RemoteExecutionLogonId
          RemoteExecutionType
          __typename
        }
        MitreInfo @include(if: $includeMitre) {
          tacticID
          tacticName
          techniqueID
          techniqueName
          __typename
        }
        ShadowITInfo @include(if: $includeShadowIT) {
          applicationName
          categoryName
          subCategoryName
          __typename
        }
        AggregationResults {
          aggregationName
          aggregateResult
          __typename
        }
        __typename
      }
      ... on GWStatsRecord @include(if: $includeGWStats) {
        DataSource
        UUID
        HostType
        MachineName
        UserName
        OSName
        OSVersion
        Base {
          RecordType
          OpTimeUTC
          GatewayName
          __typename
        }
        Network {
          NetworkType
          NetworkURL
          NetworkProtocol
          NetworkDomain
          NetworkSrcIP
          NetworkSrcPort
          NetworkDestIP
          NetworkDestPort
          NetworkConnectionDirection
          NetworkReferer
          NetworkResponseStatusCode
          NetworkUserAgent
          NetworkHttpMethod
          FileMD5
          URLReputationInfo {
            ReputationType
            Resource
            URLClassification
            URLRepTotal
            URLRepPositives
            URLRepRisk
            URLRepConfidence
            URLRepSeverity
            URLRepMalwareFamily
            URLRepProtectionName
            URLRepRegistrant
            VTLink
            __typename
          }
          DomainReputationInfo {
            ReputationType
            Resource
            DomainClassification
            DomainRepTotal
            DomainRepPositives
            DomainRepRisk
            DomainRepConfidence
            DomainRepSeverity
            DomainRepMalwareFamily
            DomainRepProtectionName
            DomainRepRegistrant
            VTLink
            __typename
          }
          DestIPReputationInfo {
            ReputationType
            Resource
            IPClassification
            IPRepTotal
            IPRepPositives
            IPRepRisk
            IPRepConfidence
            IPRepSeverity
            IPRepMalwareFamily
            IPRepGeoLocation
            VTLink
            __typename
          }
          __typename
        }
        File @include(if: $includeRecordFile) {
          FileName
          FileMD5
          FileSize
          FileReputationInfo {
            ReputationType
            Resource
            FileClassification
            FileRepPositives
            FileRepTotal
            FileRepRisk
            FileRepConfidence
            FileRepSeverity
            FileRepMalwareFamily
            FileRepMalwareTypes
            FileRepProtectionName
            VTLink
            __typename
          }
          __typename
        }
        DetectionEvent @include(if: $includeDetectionEvent) {
          DetectionAttackStatus
          DetectionEnforcementMode
          DetectionMalwareAction
          DetectionTriggeredBy
          DetectionMalwareFamily
          DetectionProtectionName
          DetectionIncidentConfidence
          DetectionIncidentSeverity
          DetectionMaliciousPath
          DetectionMaliciousFileName
          DetectionMaliciousDomainName
          DetectionTriggerMD5
          DetectionConnectionCount
          DetectionRemediationPolicy
          DetectionDescription
          __typename
        }
        MitreInfo @include(if: $includeMitre) {
          tacticID
          tacticName
          techniqueID
          techniqueName
          __typename
        }
        ShadowITInfo @include(if: $includeShadowIT) {
          applicationName
          categoryName
          subCategoryName
          __typename
        }
        __typename
      }
      ... on LAASRecord @include(if: $includeLAAS) {
        DataSource
        UUID
        HostType
        MachineName
        UserName
        OSName
        OSVersion
        Base {
          RecordType
          OpTimeUTC
          GatewayBlade
          GatewayName
          GatewayPolicyMgmt
          GatewayPolicyDate
          GatewayPolicyName
          GatewayPolicyRuleName
          GatewayPolicyRuleNumber
          GatewayPolicyRuleAction
          __typename
        }
        Network {
          NetworkType
          NetworkURL
          NetworkProtocol
          NetworkDomain
          NetworkSrcIP
          NetworkSrcPort
          NetworkDestIP
          NetworkDestPort
          NetworkConnectionDirection
          NetworkReferer
          NetworkResponseStatusCode
          NetworkUserAgent
          NetworkHttpMethod
          NetworkBytesSent
          NetworkBytesReceived
          URLReputationInfo {
            ReputationType
            Resource
            URLClassification
            URLRepTotal
            URLRepPositives
            URLRepRisk
            URLRepConfidence
            URLRepSeverity
            URLRepMalwareFamily
            URLRepProtectionName
            URLRepRegistrant
            VTLink
            __typename
          }
          DomainReputationInfo {
            ReputationType
            Resource
            DomainClassification
            DomainRepTotal
            DomainRepPositives
            DomainRepRisk
            DomainRepConfidence
            DomainRepSeverity
            DomainRepMalwareFamily
            DomainRepProtectionName
            DomainRepRegistrant
            VTLink
            __typename
          }
          DestIPReputationInfo {
            ReputationType
            Resource
            IPClassification
            IPRepTotal
            IPRepPositives
            IPRepRisk
            IPRepConfidence
            IPRepSeverity
            IPRepMalwareFamily
            IPRepGeoLocation
            VTLink
            __typename
          }
          __typename
        }
        File @include(if: $includeRecordFile) {
          FileName
          FileMD5
          FileSize
          FileReputationInfo {
            ReputationType
            Resource
            FileClassification
            FileRepPositives
            FileRepTotal
            FileRepRisk
            FileRepConfidence
            FileRepSeverity
            FileRepMalwareFamily
            FileRepMalwareTypes
            FileRepProtectionName
            VTLink
            __typename
          }
          __typename
        }
        DetectionEvent @include(if: $includeDetectionEvent) {
          DetectionAttackStatus
          DetectionEnforcementMode
          DetectionMalwareAction
          DetectionTriggeredBy
          DetectionMalwareFamily
          DetectionProtectionName
          DetectionIncidentConfidence
          DetectionIncidentSeverity
          DetectionMaliciousPath
          DetectionMaliciousFileName
          DetectionMaliciousDomainName
          DetectionTriggerMD5
          DetectionConnectionCount
          DetectionRemediationPolicy
          DetectionDescription
          DetectionSuppressedLogs
          __typename
        }
        MitreInfo @include(if: $includeMitre) {
          tacticID
          tacticName
          techniqueID
          techniqueName
          __typename
        }
        ShadowITInfo @include(if: $includeShadowIT) {
          applicationName
          categoryName
          subCategoryName
          __typename
        }
        __typename
      }
      ... on MTARecord @include(if: $includeMTA) {
        DataSource
        OSName
        HostType
        Base {
          AssetType
          OpTimeSecondsUTC
          Domain
          OpTimeUTC
          RecordType
          OSVersion
          HostType
          MachineName
          UserName
          __typename
        }
        DetectionEvent @include(if: $includeDetectionEvent) {
          DetectionEventType
          DetectionAttackStatus
          DetectionEnforcementMode
          DetectionMalwareAction
          DetectionTriggeredBy
          DetectionMalwareFamily
          DetectionProtectionName
          DetectionProtectionType
          DetectionIncidentConfidence
          DetectionIncidentSeverity
          DetectionMaliciousFileName
          DetectionMaliciousDomainName
          DetectionTriggerMD5
          DetectionTriggerURL
          DetectionDescription
          DetectionEmailMsgID
          DetectionEmailSubject
          DetectionEmailFrom
          DetectionEmailTo
          DetectionEmailAttachmentName
          DetectionEmailDateOfDelivery
          DetectionMaliciousPath
          __typename
        }
        File @include(if: $includeRecordFile) {
          FileName
          FileMD5
          FileSha1
          FileType
          FileSize
          OriginalFileClassification
          FileReputationInfo {
            ReputationType
            Resource
            FileClassification
            FileRepPositives
            FileRepTotal
            FileRepRisk
            FileRepConfidence
            FileRepSeverity
            FileRepMalwareFamily
            FileRepMalwareTypes
            FileRepProtectionName
            VTLink
            __typename
          }
          __typename
        }
        Network @include(if: $includeRecordNetwork) {
          NetworkSrcIP
          NetworkURL
          NetworkAction
          NetworkDomain
          NetworkType
          URLReputationInfo {
            ReputationType
            Resource
            URLClassification
            URLRepTotal
            URLRepPositives
            URLRepRisk
            URLRepConfidence
            URLRepSeverity
            URLRepMalwareFamily
            URLRepProtectionName
            URLRepRegistrant
            VTLink
            __typename
          }
          DomainReputationInfo {
            ReputationType
            Resource
            DomainClassification
            DomainRepTotal
            DomainRepPositives
            DomainRepRisk
            DomainRepConfidence
            DomainRepSeverity
            DomainRepMalwareFamily
            DomainRepProtectionName
            DomainRepRegistrant
            VTLink
            __typename
          }
          DestIPReputationInfo {
            ReputationType
            Resource
            IPClassification
            IPRepTotal
            IPRepPositives
            IPRepRisk
            IPRepConfidence
            IPRepSeverity
            IPRepMalwareFamily
            IPRepGeoLocation
            VTLink
            __typename
          }
          __typename
        }
        Email {
          EmailRule
          EmailStatus
          EmailClassification
          EmailReason
          EmailId
          EmailTo
          EmailFrom
          EmailSrcIP
          EmailStatus
          EmailSubject
          EmailQueueId
          EmailReplyTo
          EmailMessageId
          EmailAttachments
          EmailURLsCount
          EmailRecipientsNum
          EmailSourceCountry
          EmailInspectionType
          EmailConfidence
          __typename
        }
        __typename
      }
      ... on MobileRecord {
        DataSource
        UUID
        OSName
        HostType
        OSVersion
        ProductVersion
        MachineName
        HostType
        UserName
        Base {
          DeviceRisk
          RecordType
          OpTimeUTC
          DeviceID
          DeviceVendor
          Model
          DeviceModel
          HardwareModel
          ONPVersion
          ONPProtection
          SSLInspection
          SafeDNSProtection
          LocationLatitude
          LocationLongitude
          Location
          Locale
          LocaleDisplayName
          RootingJB
          USBDebugging
          DeviceEncryption
          ScreenLockProtection
          VerifiedBoot
          SELinux
          MDMVendor
          MDMDeviceID
          ManagedDevice
          ManagedDeviceType
          ExternalIP
          Wifi
          Cellular
          __typename
        }
        DetectionEvent {
          DetectionTriggeredBy
          DetectionAttackStatus
          DetectionMaliciousPath
          EventTrigger
          EventDetails
          ThreatFactors
          AttackVector
          OldRiskLevel
          NewRiskLevel
          ONPAction
          ONPActionReason
          IsOtherVPNAlwaysOn
          __typename
        }
        Network {
          NetworkType
          NetworkEventType
          NetworkSrcPort
          NetworkDestIP
          NetworkDestPort
          NetworkProtocol
          AppProtocol
          SSLVersion
          SSLPeerCertCN
          SSLPeerCertSHA256
          SSLValidity
          SourceAppID
          SourceAppSHA256
          NetworkDomain
          OpenTime
          CloseTime
          NetworkBytesSent
          NetworkBytesReceived
          DNSResponse
          DNSRequestedType
          NetworkReferer
          NetworkUserAgent
          NetworkHttpMethod
          HttpMimeType
          IsBrowser
          ReputationRisk
          ReputationSafe
          ReputationCategories
          NetworkURL
          ZPPageIndicators
          ZPUniqueID
          ZPVerdictRisk
          ZPVerdictUUID
          ZPVerdictImpostureTargetBrand
          ZPVerdictImpostureTargetDomain
          ZPVerdictImpostureTargetType
          ZPAction
          InjectionTime
          ScanTime
          URLReputationInfo {
            ReputationType
            Resource
            URLClassification
            URLRepTotal
            URLRepPositives
            URLRepRisk
            URLRepConfidence
            URLRepSeverity
            URLRepMalwareFamily
            URLRepProtectionName
            URLRepRegistrant
            VTLink
            __typename
          }
          DomainReputationInfo {
            ReputationType
            Resource
            DomainClassification
            DomainRepTotal
            DomainRepPositives
            DomainRepRisk
            DomainRepConfidence
            DomainRepSeverity
            DomainRepMalwareFamily
            DomainRepProtectionName
            DomainRepRegistrant
            VTLink
            __typename
          }
          DestIPReputationInfo {
            ReputationType
            Resource
            IPClassification
            IPRepTotal
            IPRepPositives
            IPRepRisk
            IPRepConfidence
            IPRepSeverity
            IPRepMalwareFamily
            IPRepGeoLocation
            VTLink
            __typename
          }
          __typename
        }
        NetworkRoaming {
          JoinTime
          NetworkInterfaceType
          WifiSSID
          WifiBSSID
          DefaultGatewayIP
          NetworkOperator
          NetworkOperatorName
          SimCarrierId
          SimCarrierIdName
          SimOperator
          SimOperatorName
          SimSpecificCarrierId
          SimSpecificCarrierIdName
          __typename
        }
        Application {
          AppActionTime
          AppAction
          AppID
          AppPackageName
          AppVersion
          AppInstallationSource
          AppCertificate
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}
'

    $bodyObj = @{
        operationName = "searchRecords";
        variables     = $variables;
        query         = $query
    }
    $body = $bodyObj | ConvertTo-Json -Depth 20

    $res = Invoke-RestMethod -Uri $url `
        -Method Post `
        -Headers $headers `
        -Body $body 

    $res.data.searchRecords
}

function Get-CpThIncidentReport($reportId) {
    $url = "https://cloudinfra-gw.portal.checkpoint.com/app/endpoint-web-mgmt/webmgmt/graphql" 
    $portalToken = $Script:cpPortalToken
    $epmToken = $Script:cpEpmToken
    
    $headers = @{
        'Content-Type'  = 'application/json';
        'Authorization' = "Bearer $portalToken";
        token           = $epmToken
    }

    $variables = @{ reportId = $reportId } 
    
    $query = '
    query getForensicsReportDetails($reportId: String!) {
        getForensicsReportDetails(incidentId: $reportId, timeFrame: "all-time") {
          incidentLog
          fileName
        }
      }'

    $body = @{
        operationName = "getForensicsReportDetails";
        variables     = $variables;
        query         = $query
    } | ConvertTo-Json -Depth 20

    $res = Invoke-RestMethod -Uri $url `
        -Method Post `
        -Headers $headers `
        -Body $body

    $res.data.getForensicsReportDetails
}

function Out-CpThIncidentReport($incidentLogBase64Str, $zipFilename) {
    $decoded1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($incidentLogBase64Str))
    $decoded2 = [System.Convert]::FromBase64String($decoded1)
    [IO.File]::WriteAllBytes($zipFilename, $decoded2) 
}

function Demo-IncidentList {
    # login with TH key to get list of incidents
    Write-Host "Login to Infinity Portal with TH key"
    New-CPPortalSession $TH_KEY $TH_SECRET | Out-Null
    # get list
    Write-Host "Getting list of incidents"
    $incidentList = (Get-CpThIncident).records 
    $incidentList | select MachineName, @{n = "ProcessName"; e = { $_.Base.ProcessName } }, 
        @{n = "Trigger"; e = { $_.DetectionEvent.DetectionTriggeredBy } }, 
        @{n = "ProtectionName"; e = { $_.DetectionEvent.DetectionProtectionName } },
        @{n = "iid"; e = { $_.DetectionEvent.DetectionIncidentId } }     
}

function Demo-SelectIncident {
    $list =  Demo-IncidentList
    $incident = $list | Out-ConsoleGridView -OutputMode Single
    Write-Host "Selected $($incident.iid)"
    Write-Host "Getting full list"
    $fullList = (Get-CpThIncident).records 
    $fullData = $fullList | ? {$_.DetectionEvent.DetectionIncidentId -eq $incident.iid }
    Write-Host "Incident details:"
    $fullData | ConvertTo-Json -Depth 20
}
function Demo-CpThReportDownloadOne {
    # login with TH key to get list of incidents
    Write-Host "Login to Infinity Portal with TH key"
    New-CPPortalSession $TH_KEY $TH_SECRET | Out-Null
    # get list
    Write-Host "Getting list of incidents"
    $incidentList = (Get-CpThIncident).records 
    $count = ($incidentList | Measure-Object).Count
    Write-Host "Got $count records"
    # get ID of first one
    $iid = $incidentList | % { $_.DetectionEvent.DetectionIncidentId } | Select-Object -First 1 
    Write-Host "First incident ID is $iid"
    # API for forensics report download is EPM, login first with EP keys
    Write-Host "Login to Infinity Portal with EP key"
    New-CPPortalSession $EP_KEY $EP_SECRET | Out-Null
    # need session on EPM too; based on portal identity
    Write-Host "Login to EPM service"
    New-CpEpmSession | Out-Null
    # download report in base64 string
    Write-Host "Downloading report for IID $iid"
    $resp = Get-CpThIncidentReport $iid
    # decode and save to ZIP
    Write-Host "Saving report for IID $iid"
    Out-CpThIncidentReport $resp.incidentLog "$iid.zip"
    
    Write-Host "Download done. Look at $iid.zip"
    ls "$iid.zip"
}

function Demo-CpThReportDownloadAll {
    # login with TH key to get list of incidents
    Write-Host "Login to Infinity Portal with TH key"
    New-CPPortalSession $TH_KEY $TH_SECRET | Out-Null
    # get list
    Write-Host "Getting list of incidents"
    $incidentList = (Get-CpThIncident).records 
    $count = ($incidentList | Measure-Object).Count
    Write-Host "Got $count records"
    # visit every single incident
    $incidentList | % { $_.DetectionEvent.DetectionIncidentId } | ForEach-Object {
        $iid = $_
        Write-Host "Processing incident $iid"
        # API for forensics report download is EPM, login first with EP keys
        Write-Host "Login to Infinity Portal with EP key"
        New-CPPortalSession $EP_KEY $EP_SECRET | Out-Null
        # need session on EPM too; based on portal identity
        Write-Host "Login to EPM service"
        New-CpEpmSession | Out-Null
        # download report in base64 string
        Write-Host "Downloading report for IID $iid"
        $resp = Get-CpThIncidentReport $iid
        # decode and save to ZIP
        Write-Host "Saving report for IID $iid"
        Out-CpThIncidentReport $resp.incidentLog "$iid.zip"
        
        Write-Host "Download done. Look at $iid.zip"
        ls "$iid.zip"
    }
    Write-Host "Done."
}