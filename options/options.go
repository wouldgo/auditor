package options

import (
	logFacility "auditor/logger"
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
	eigthHours, _           = time.ParseDuration("8h")
	defaultModelMergersTime = 200 * time.Millisecond
	executableDefaultName   = os.Args[0]

	dnsEnv, dnsEnvSet = os.LookupEnv("DNS")
	dns               = flag.String("dns", "1.1.1.1:53", "DNS server to use")

	shodanApiKeyEnv, shodanApiKeyEnvSet = os.LookupEnv("SHODAN_API_KEY")
	shodanApiKey                        = flag.String("shodan-api-key", "", "Shodan API key to use")

	cacheSizeEnv, cacheSizeEnvSet = os.LookupEnv("CACHE_SIZE")
	cacheSize                     = flag.Int("cache-size", 1024, "LRU cache for meta gathering")

	cacheEvictionEnv, cacheEvictionEnvSet = os.LookupEnv("CACHE_EVICTION")
	cacheEviction                         = flag.Duration("cache-eviction", eigthHours, "LRU cache cache duration")

	applicatioNameEnv, applicationNameEnvSet = os.LookupEnv("APPLICATION_NAME")
	applicationName                          = flag.String("application-name", executableDefaultName, "Application name. Defaults to executable name")

	pathWhereStoreDatabaseFileEnv, pathWhereStoreDatabaseFileEnvSet = os.LookupEnv("DATABASE_FILE")
	pathWhereStoreDabaseFile                                        = flag.String("database-file", os.TempDir(), "Folder where store database file. Defaults to OS temp")

	logEnvironmentEnv, logEnvironmentEnvSet = os.LookupEnv("LOG_ENVIRONMENT")
	logEnvironment                          = flag.String("log-environment", "", "Log environment")

	autocomplete = flag.Bool("zsh-autocomplete", false, "Print zsh autocomplete")
)

type OptionsBase struct {
	Model  *model.ModelConfigurations
	Meta   *meta.MetaConfiguration
	Logger *logFacility.Logger
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

		return nil, errors.New("shodan api key must be present")
	}

	if pathWhereStoreDatabaseFileEnvSet {
		pathWhereStoreDabaseFile = &pathWhereStoreDatabaseFileEnv
	}

	if applicationNameEnvSet {
		applicationName = &applicatioNameEnv
	}

	metaConf := &meta.MetaConfiguration{
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
		Model: &model.ModelConfigurations{
			PathWhereStoreDabaseFile: pathWhereStoreDabaseFile,
			ApplicationName:          applicationName,
			ModelMergersTime:         defaultModelMergersTime,
		},
		Meta: metaConf,
		Logger: &logFacility.Logger{
			Log: sugar,
		},
	}

	return opts, nil
}

func printCompletions(name *string) {
	var cmpl []string
	flag.VisitAll(func(f *flag.Flag) {
		cmpl = append(
			cmpl, fmt.Sprintf("\t'-%s[%s]' \\\n", f.Name, f.Usage))
	})

	args := fmt.Sprintf("#compdef %s\n\n_arguments -s \\\n%s\n\n",
		*name, strings.Join(cmpl, " "))
	fmt.Print(args)
}
