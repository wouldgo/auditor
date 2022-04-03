package options

import (
	"auditor/meta"
	"auditor/model"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

var (
	tmpDir        = os.TempDir()
	eigthHours, _ = time.ParseDuration("8h")

	dnsEnv, dnsEnvSet = os.LookupEnv("DNS")
	dns               = flag.String("dns", "1.1.1.1:53", "DNS server to use")

	shodanApiKeyEnv, shodanApiKeyEnvSet = os.LookupEnv("SHODAN_API_KEY")
	shodanApiKey                        = flag.String("shodan-api-key", "", "Shodan API key to use")

	cacheSizeEnv, cacheSizeEnvSet = os.LookupEnv("CACHE_SIZE")
	cacheSize                     = flag.Int("cache-size", 1024, "LRU cache for meta gathering")

	cacheEvictionEnv, cacheEvictionEnvSet = os.LookupEnv("CACHE_EVICTION")
	cacheEviction                         = flag.Duration("cache-eviction", eigthHours, "LRU cache cache duration")

	logEnvironmentEnv, logEnvironmentEnvSet = os.LookupEnv("LOG_ENVIRONMENT")
	logEnvironment                          = flag.String("log-environment", "", "Log environment")

	postgresqlAdministratorEnv, postgresqlAdministratorEnvSet                 = os.LookupEnv("POSTGRESQL_ADMINISTRATOR")
	postgresqlAdministrator                                                   = flag.String("postgresql-administrator", "", "postgresql database administrator username")
	postgresqlAdministratorPasswordEnv, postgresqlAdministratorPasswordEnvSet = os.LookupEnv("POSTGRESQL_ADMINISTRATOR_PASSWORD")
	postgresqlAdministratorPassword                                           = flag.String("postgresql-administrator-password", "", "postgresql database administrator password")
	postgresqlHostEnv, postgresqlHostEnvSet                                   = os.LookupEnv("POSTGRESQL_HOST")
	postgresqlHost                                                            = flag.String("postgresql-host", "", "hostname of postgresql server")
	postgresqlDatabaseEnv, postgresqlDatabaseEnvSet                           = os.LookupEnv("POSTGRESQL_DATABASE")
	postgresqlDatabase                                                        = flag.String("postgresql-database", "", "postgresql database name")
	postgresqlUsernameEnv, postgresqlUsernameEnvSet                           = os.LookupEnv("POSTGRESQL_USERNAME")
	postgresqlUsername                                                        = flag.String("postgresql-username", "", "postgresql user")
	postgresqlPasswordEnv, postgresqlPasswordEnvSet                           = os.LookupEnv("POSTGRESQL_PASSWORD")
	postgresqlPassword                                                        = flag.String("postgresql-password", "", "postgresql password")
	postgresqlThreadsEnv, postgresqlThreadsEnvSet                             = os.LookupEnv("POSTGRESQL_THREADS")
	postgresqlThreads                                                         = flag.Int("postgresql-threads", 1, "number of thread for postgresql client")

	autocomplete = flag.Bool("zsh-autocomplete", false, "Print zsh autocomplete")
)

type OptionsBase struct {
	Meta *meta.MetaConfiguration

	Log *zap.SugaredLogger
}

func Parse() (*OptionsBase, error) {
	var parentConfig zap.Config

	flag.Parse()

	if logEnvironmentEnvSet {
		logEnvironment = &logEnvironmentEnv
	}

	if strings.EqualFold(*logEnvironment, "production") {
		parentConfig = zap.NewProductionConfig()
	} else {
		parentConfig = zap.NewDevelopmentConfig()
	}

	config := zap.Config{
		Level:            parentConfig.Level,
		Encoding:         "console",
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    parentConfig.EncoderConfig,
	}

	logger, err := config.Build()

	if err != nil {
		return nil, err
	}

	defer logger.Sync()
	sugar := logger.Sugar()

	if dnsEnvSet {
		dns = &dnsEnv
	}

	if cacheSizeEnvSet {
		cacheSizeFromEnv, err := strconv.ParseInt(cacheSizeEnv, 10, 32)
		if err != nil {
			return nil, err
		}

		*cacheSize = int(cacheSizeFromEnv)
	}

	if cacheEvictionEnvSet {
		cacheEvictionFromEnv, err := time.ParseDuration(cacheEvictionEnv)
		if err != nil {
			return nil, err
		}

		*cacheEviction = cacheEvictionFromEnv
	}

	if shodanApiKeyEnvSet {
		shodanApiKey = &shodanApiKeyEnv
	}

	if strings.EqualFold(*shodanApiKey, "") {

		return nil, errors.New("Shodan api key must be present")
	}

	if postgresqlAdministratorEnvSet {
		postgresqlAdministrator = &postgresqlAdministratorEnv
	}

	if postgresqlAdministratorPasswordEnvSet {
		postgresqlAdministratorPassword = &postgresqlAdministratorPasswordEnv
	}

	if postgresqlHostEnvSet {
		postgresqlHost = &postgresqlHostEnv
	}

	if postgresqlDatabaseEnvSet {
		postgresqlDatabase = &postgresqlDatabaseEnv
	}

	if postgresqlUsernameEnvSet {
		postgresqlUsername = &postgresqlUsernameEnv
	}

	if postgresqlPasswordEnvSet {
		postgresqlPassword = &postgresqlPasswordEnv
	}

	if postgresqlThreadsEnvSet {
		postgresqlThreadsFromEnv, err := strconv.ParseInt(postgresqlThreadsEnv, 10, 32)
		if err != nil {
			return nil, err
		}

		*postgresqlThreads = int(postgresqlThreadsFromEnv)
	}

	if postgresqlAdministrator == nil ||
		postgresqlAdministratorPassword == nil ||
		postgresqlHost == nil ||
		postgresqlDatabase == nil ||
		postgresqlUsername == nil ||
		postgresqlPassword == nil ||
		strings.EqualFold(*postgresqlAdministrator, "") ||
		strings.EqualFold(*postgresqlAdministratorPassword, "") ||
		strings.EqualFold(*postgresqlHost, "") ||
		strings.EqualFold(*postgresqlDatabase, "") ||
		strings.EqualFold(*postgresqlUsername, "") ||
		strings.EqualFold(*postgresqlPassword, "") {

		return nil, errors.New("Postgresql configuration is not set")
	}

	applicationName, err := os.Executable()
	if err != nil {

		return nil, err
	}
	metaConf := &meta.MetaConfiguration{
		PostgresqlConfigurations: &model.PostgresqlConfigurations{
			Administrator:         postgresqlAdministrator,
			AdministratorPassword: postgresqlAdministratorPassword,
			Host:                  postgresqlHost,
			Database:              postgresqlDatabase,
			Username:              postgresqlUsername,
			Password:              postgresqlPassword,
			Threads:               postgresqlThreads,
			ApplicationName:       applicationName,
		},
		ShodanApiKey:  shodanApiKey,
		CacheSize:     cacheSize,
		CacheEviction: cacheEviction,

		Dns: dns,
	}

	if *autocomplete {
		printCompletions(applicationName)
		return &OptionsBase{}, nil
	}
	opts := &OptionsBase{
		Meta: metaConf,
		Log:  sugar,
	}

	return opts, nil
}

func printCompletions(name string) {
	var cmpl []string
	flag.VisitAll(func(f *flag.Flag) {
		cmpl = append(
			cmpl, fmt.Sprintf("\t'-%s[%s]' \\\n", f.Name, f.Usage))
	})

	args := fmt.Sprintf("#compdef %s\n\n_arguments -s \\\n%s\n\n",
		name, strings.Join(cmpl, " "))
	fmt.Print(args)
}
