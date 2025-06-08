package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaptypes"
	"github.com/savely-krasovsky/go-ctaphid/pkg/options"
	"github.com/savely-krasovsky/go-ctaphid/pkg/sugar"
)

func main() {
	lvl := new(slog.LevelVar)
	lvl.Set(slog.LevelDebug)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	}))

	dev, err := sugar.SelectDevice(
		// Comment if you are using Linux or macOS
		//options.WithUseNamedPipes(),
		options.WithLogger(logger),
	)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = dev.Close()
	}()

	retries, powerCycleRequired, err := dev.GetPINRetries()
	if err != nil {
		panic(err)
	}
	fmt.Printf("PIN retries: %d\n", retries)
	fmt.Printf("Power cycle required: %t\n", powerCycleRequired)

	token, err := dev.GetPinUvAuthTokenUsingPIN(
		"12345678",
		ctaptypes.PermissionCredentialManagement,
		"",
	)
	if err != nil {
		panic(err)
	}

	metadata, err := dev.GetCredsMetadata(token)
	if err != nil {
		panic(err)
	}
	fmt.Printf(
		"Passkeys: %d (%d left)\n",
		metadata.ExistingResidentCredentialsCount,
		metadata.MaxPossibleRemainingResidentCredentialsCount,
	)

	rps := make([]*ctaptypes.AuthenticatorCredentialManagementResponse, 0)
	for rp, err := range dev.EnumerateRPs(token) {
		if err != nil {
			panic(err)
		}

		rps = append(rps, rp)
	}

	creds := make([]*ctaptypes.AuthenticatorCredentialManagementResponse, 0)
	for i, rp := range rps {
		for cred, err := range dev.EnumerateCredentials(token, rp.RPIDHash) {
			if err != nil {
				panic(err)
			}

			fmt.Printf("%d) %s: %s / %s / %s\n",
				i+1,
				rp.RP.ID,
				string(cred.User.ID),
				cred.User.Name,
				cred.User.DisplayName,
			)

			creds = append(creds, cred)
		}
	}
}
