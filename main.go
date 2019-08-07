package main

import (
	"github.com/cmoreira-daitan/terraform-provider-awspresence/awspresence"
	"github.com/hashicorp/terraform/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: awspresence.Provider})
}
