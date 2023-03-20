package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cloudbase/garm-provider-azure/provider"
	"github.com/cloudbase/garm/runner/providers/external/execution"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), signals...)
	defer stop()

	executionEnv, err := execution.GetEnvironment()
	if err != nil {
		log.Fatal(err)
	}

	prov, err := provider.NewAzureProvider(executionEnv.ProviderConfigFile, executionEnv.ControllerID)
	if err != nil {
		log.Fatal(err)
	}

	result, err := execution.Run(ctx, prov, executionEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to run command: %+v\n", err)
		os.Exit(1)
	}
	if len(result) > 0 {
		fmt.Fprint(os.Stdout, result)
	}
}
