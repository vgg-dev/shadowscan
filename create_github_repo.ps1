[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$false)]
  [string]$RepoName = "shadowscan",

  [Parameter(Mandatory=$false)]
  [ValidateSet('private','public')]
  [string]$Visibility = "private",

  [Parameter(Mandatory=$false)]
  [string]$Description = "ShadowScan: tiny CLI that queries Shodan Host API and prints Nmap-style output.",

  # If set, creates the repo under the org instead of your user.
  [Parameter(Mandatory=$false)]
  [string]$Org,

  # Optional GitHub token; if omitted, uses env vars GITHUB_TOKEN, GH_TOKEN, or GITHUB_PAT.
  [Parameter(Mandatory=$false)]
  [string]$Token,

  [Parameter(Mandatory=$false)]
  [string]$RemoteName = "origin"
)

$ErrorActionPreference = 'Stop'

function Require-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $Name"
  }
}

function Get-GitBranch {
  $b = (git rev-parse --abbrev-ref HEAD 2>$null)
  if (-not $b) { throw "Not a git repo (or no commits yet). Run from inside the project folder." }
  return $b.Trim()
}

function Get-Token {
  param([string]$ExplicitToken)
  if ($ExplicitToken) { return $ExplicitToken }
  if ($env:GITHUB_TOKEN) { return $env:GITHUB_TOKEN }
  if ($env:GH_TOKEN) { return $env:GH_TOKEN }
  if ($env:GITHUB_PAT) { return $env:GITHUB_PAT }
  throw "Missing GitHub token. Set `$env:GITHUB_TOKEN (or `$env:GH_TOKEN) to a token with repo permissions, or pass -Token."
}

Require-Command git

$tokenValue = Get-Token -ExplicitToken $Token
$headers = @{ Authorization = "Bearer $tokenValue"; Accept = "application/vnd.github+json" }

# Determine owner
if ($Org) {
  $owner = $Org
  $createUri = "https://api.github.com/orgs/$Org/repos"
} else {
  $me = Invoke-RestMethod -Method Get -Uri "https://api.github.com/user" -Headers $headers
  $owner = $me.login
  if (-not $owner) { throw "Could not determine GitHub username from token." }
  $createUri = "https://api.github.com/user/repos"
}

$private = ($Visibility -eq 'private')
$body = @{ name = $RepoName; description = $Description; private = $private; auto_init = $false } | ConvertTo-Json

Write-Host "Owner: $owner"
Write-Host "Repo:  $RepoName ($Visibility)"

if ($PSCmdlet.ShouldProcess("GitHub", "Create repo $owner/$RepoName")) {
  try {
    $repo = Invoke-RestMethod -Method Post -Uri $createUri -Headers $headers -Body $body
    Write-Host "Created: $($repo.html_url)"
  } catch {
    Write-Warning ("Create failed: " + $_.Exception.Message)
  }
}

$remoteUrl = "https://github.com/$owner/$RepoName.git"

# Ensure remote
$existing = (git remote 2>$null) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if ($existing -notcontains $RemoteName) {
  if ($PSCmdlet.ShouldProcess("git", "Add remote $RemoteName")) {
    git remote add $RemoteName $remoteUrl
  }
} else {
  if ($PSCmdlet.ShouldProcess("git", "Set remote $RemoteName URL")) {
    git remote set-url $RemoteName $remoteUrl
  }
}

$branch = Get-GitBranch

Write-Host "Pushing branch '$branch' -> '$RemoteName'..."
Write-Host "(If prompted, authenticate via your GitHub credential manager/browser.)"

if ($PSCmdlet.ShouldProcess("git", "Push to $remoteUrl")) {
  git push -u $RemoteName $branch
}
