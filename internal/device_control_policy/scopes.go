package devicecontrolpolicy

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var apiScopesReadWrite = []scopes.Scope{
	{
		Name:  "Device Control Policies",
		Read:  true,
		Write: true,
	},
}
