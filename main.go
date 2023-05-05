// Copyright 2023 Cloudbase Solutions SRL
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudbase/garm-provider-azure/internal/util"
	"github.com/cloudbase/garm-provider-azure/provider"
	"github.com/cloudbase/garm/runner/providers/external/execution"
)

var signals = []os.Signal{
	os.Interrupt,
	syscall.SIGTERM,
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), signals...)
	defer stop()

	util.SetupLogging()

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
