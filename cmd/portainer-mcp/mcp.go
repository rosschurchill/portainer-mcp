package main

import (
	"flag"
	"os"
	"strings"

	"github.com/portainer/portainer-mcp/internal/mcp"
	"github.com/portainer/portainer-mcp/internal/tooldef"
	"github.com/portainer/portainer-mcp/pkg/secrets/vault"
	"github.com/rs/zerolog/log"
)

const defaultToolsPath = "tools.yaml"

var (
	Version   string
	BuildDate string
	Commit    string
)

func main() {
	log.Info().
		Str("version", Version).
		Str("build-date", BuildDate).
		Str("commit", Commit).
		Msg("Portainer MCP server")

	serverFlag := flag.String("server", "", "The Portainer server URL")
	tokenFlag := flag.String("token", "", "The authentication token for the Portainer server")
	tokenFileFlag := flag.String("token-file", "", "Path to a file containing the authentication token")
	toolsFlag := flag.String("tools", "", "The path to the tools YAML file")
	readOnlyFlag := flag.Bool("read-only", false, "Run in read-only mode")
	disableVersionCheckFlag := flag.Bool("disable-version-check", false, "Disable Portainer server version check")
	skipTLSFlag := flag.Bool("skip-tls-verify", false, "Skip TLS certificate verification when connecting to Portainer (not recommended for production)")

	// Vault integration flags (all optional)
	vaultAddrFlag := flag.String("vault-addr", "", "The HashiCorp Vault server address (e.g., https://vault.example.com:8200)")
	vaultRoleIDFlag := flag.String("vault-role-id", "", "The Vault AppRole role_id for authentication")
	vaultSecretIDFlag := flag.String("vault-secret-id", "", "The Vault AppRole secret_id for authentication")
	vaultSkipTLSFlag := flag.Bool("vault-skip-tls", false, "Skip TLS verification for Vault connection")
	vaultMountPathFlag := flag.String("vault-mount-path", "approle", "The Vault AppRole auth mount path")

	flag.Parse()

	if *serverFlag == "" {
		log.Fatal().Msg("-server flag is required")
	}

	token := *tokenFlag
	if token == "" && *tokenFileFlag != "" {
		data, err := os.ReadFile(*tokenFileFlag)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to read token file")
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		token = os.Getenv("PORTAINER_TOKEN")
	}
	if token == "" {
		log.Fatal().Msg("Token is required: use -token flag, -token-file flag, or PORTAINER_TOKEN environment variable")
	}

	// Validate vault flags: all-or-none
	vaultFlagsSet := *vaultAddrFlag != "" || *vaultRoleIDFlag != "" || *vaultSecretIDFlag != ""
	if vaultFlagsSet {
		if *vaultAddrFlag == "" || *vaultRoleIDFlag == "" || *vaultSecretIDFlag == "" {
			log.Fatal().Msg("All vault flags (-vault-addr, -vault-role-id, -vault-secret-id) are required when using Vault integration")
		}
	}

	toolsPath := *toolsFlag
	if toolsPath == "" {
		toolsPath = defaultToolsPath
	}

	// We first check if the tools.yaml file exists
	// We'll create it from the embedded version if it doesn't exist
	exists, err := tooldef.CreateToolsFileIfNotExists(toolsPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create tools.yaml file")
	}

	if exists {
		log.Info().Msg("using existing tools.yaml file")
	} else {
		log.Info().Msg("created tools.yaml file")
	}

	log.Info().
		Str("portainer-host", *serverFlag).
		Str("tools-path", toolsPath).
		Bool("read-only", *readOnlyFlag).
		Bool("disable-version-check", *disableVersionCheckFlag).
		Bool("skip-tls-verify", *skipTLSFlag).
		Msg("starting MCP server")

	// Build server options
	serverOpts := []mcp.ServerOption{
		mcp.WithReadOnly(*readOnlyFlag),
		mcp.WithDisableVersionCheck(*disableVersionCheckFlag),
		mcp.WithSkipTLSVerify(*skipTLSFlag),
	}

	// Initialize Vault client if configured
	if vaultFlagsSet {
		vaultOpts := []vault.ClientOption{
			vault.WithSkipTLSVerify(*vaultSkipTLSFlag),
			vault.WithMountPath(*vaultMountPathFlag),
		}

		vaultClient, err := vault.NewVaultClient(*vaultAddrFlag, *vaultRoleIDFlag, *vaultSecretIDFlag, vaultOpts...)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to connect to Vault")
		}
		defer vaultClient.Close()

		serverOpts = append(serverOpts, mcp.WithSecretsProvider(vaultClient))
		log.Info().Str("vault-addr", *vaultAddrFlag).Msg("vault integration enabled")
	}

	server, err := mcp.NewPortainerMCPServer(*serverFlag, token, toolsPath, serverOpts...)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create server")
	}

	server.AddEnvironmentFeatures()
	server.AddEnvironmentGroupFeatures()
	server.AddTagFeatures()
	server.AddStackFeatures()
	server.AddLocalStackFeatures()
	server.AddSettingsFeatures()
	server.AddUserFeatures()
	server.AddTeamFeatures()
	server.AddAccessGroupFeatures()
	server.AddDockerProxyFeatures()
	server.AddKubernetesProxyFeatures()
	server.AddVaultFeatures()

	err = server.Start()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to start server")
	}
}
