# IntelliJ's Go plugin can inject the host SDK into a container terminal after
# reading startup files. Discard those overrides before shell integration runs.
unset _INTELLIJ_FORCE_SET_GOROOT _INTELLIJ_FORCE_SET_GOPATH
export GOROOT=/usr/local/go
export GOPATH=/go
