param(
    [Parameter(Mandatory = $false)]
    [string]$PublicBaseUrl,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [int]$Port = 8766
)

if (-not $PublicBaseUrl) {
    $PublicBaseUrl = Read-Host "MCP Public Base URL (z.B. https://abc.trycloudflare.com)"
}

if (-not $ClientId) {
    $ClientId = Read-Host "GitHub OAuth Client ID"
}

if (-not $ClientSecret) {
    $ClientSecret = Read-Host "GitHub OAuth Client Secret"
}

if (-not $PublicBaseUrl -or -not $ClientId -or -not $ClientSecret) {
    throw "PublicBaseUrl, ClientId und ClientSecret sind erforderlich."
}

$env:MCP_AUTH_MODE = "github"
$env:MCP_PUBLIC_BASE_URL = $PublicBaseUrl
$env:MCP_OAUTH_CLIENT_ID = $ClientId
$env:MCP_OAUTH_CLIENT_SECRET = $ClientSecret
$env:MCP_OAUTH_SCOPES = "read:user,user:email"
$env:MCP_PORT = "$Port"

py -3 .\scripts\mcp_readonly_evoki.py
