package main

import (
	"context"
	"encoding/json"
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

	prov, err := provider.NewAzureProvider(executionEnv)
	if err != nil {
		log.Fatal(err)
	}

	switch executionEnv.Command {
	case execution.CreateInstanceCommand:
		instance, err := prov.CreateInstance(ctx, executionEnv.BootstrapParams)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create instance: %s", err)
			os.Exit(1)
		}

		asJs, err := json.Marshal(instance)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to marshal response: %s", err)
			os.Exit(1)
		}
		fmt.Fprint(os.Stdout, string(asJs))
	case execution.GetInstanceCommand:
	case execution.ListInstancesCommand:
	case execution.DeleteInstanceCommand:
	case execution.RemoveAllInstancesCommand:
	case execution.StartInstanceCommand:
	case execution.StopInstanceCommand:
	default:
		fmt.Fprintf(os.Stderr, "invalid command: %s", executionEnv.Command)
		os.Exit(1)
	}
	fmt.Println(prov)
}
