$Script_path = $MyInvocation.MyCommand.Definition
$script_folder = Split-Path -Path $Script_path -Parent
$script_name = Split-Path -Path $Script_path -Leaf
$parameters = Get-Content -Path "$script_folder\config.json" -Raw | ConvertFrom-Json

"Script Path: $Script_path"
"Script Folder: $Script_folder"
"Script Name: $script_name"

function Get_AuthCode{
  $AuthCode_uri = $parameters.authcodeURI
  Start-Process -FilePath $AuthCode_uri
  $parameters.AuthorizationCode = read-Host -Prompt 'paste Authorization code from Website'
}

function Get_Token{
    
  $requestUri = $parameters.requestUri
  $ClientID = $parameters.ClientID
  $Secret = $parameters.Secret
  $redirect_uri = $parameters.redirect_uri
  $AuthorizationCode = $parameters.AuthorizationCode    
    
  $token_Params = @{
    client_id = $ClientID
    client_secret = $Secret
    code=$AuthorizationCode
    grant_type='authorization_code'
    redirect_uri=$redirect_uri
  }
    
  $Token = ''
    
  try
  {
    $Token = Invoke-RestMethod -Uri $requestUri -Method POST -Body $token_Params -ErrorAction Stop
  }
  catch [Net.WebException]
  {
    # get error record
    [Management.Automation.ErrorRecord]$e = $_

    # retrieve information about runtime error
    $info = New-Object -TypeName PSObject -Property @{
      Exception = $e.Exception.Message
      Reason    = $e.CategoryInfo.Reason
      Target    = $e.CategoryInfo.TargetName
      Script    = $e.InvocationInfo.ScriptName
      Line      = $e.InvocationInfo.ScriptLineNumber
      Column    = $e.InvocationInfo.OffsetInLine
    }
      
    # output information. Post-process collected info, and log info (optional)
    $info
  }

  $Token.refesh_token > "$Script_folder\refreshToken.txt"
  $Token.access_token > "$Script_folder\accessToken.txt"
  
  return $token   
}

function Get_RefreshToken {

  [string]$requestUri = $parameters.requestUri  
  [string]$refresh_token = Get-Content -Path "$Script_folder\refreshToken.txt"  
  
  $refreshToken_Params = @{
    client_id = $parameters.ClientID
    client_secret = $parameters.Secret
    refresh_token = $refresh_token
    grant_type = 'refresh_token'
    content_type = 'application/x-www-form-urlencoded'
  }
  
  $token = Invoke-RestMethod -Uri $requestUri -Method Post -Body $refreshToken_Params
  
  "Token: $token"  
  $Token.access_token > "$Script_folder\accessToken.txt"
  gc "$Script_folder\accessToken.txt"
}

function Get_Info {
  [CmdletBinding()]
  param(
    [string] $request_uri = 'https://www.googleapis.com/gmail/v1/users/me/',
    [string] $data = 'threads' #default to get labels 
  )
  $access_token = Get-Content -Path "$script_folder/accessToken.txt"
  
  $access_token_params=@{
    Authorization = "Bearer $access_token"
    contentType = 'application/json'
  }
    
  $Request = Invoke-RestMethod -Uri "$request_uri$data" -Headers $access_token_params -Method Get 
  
  Return $Request
  
}
#$token = Get_Token
#$data = Get_Info
#$data

#Get_RefreshToken
