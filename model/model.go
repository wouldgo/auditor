package model

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/httpfs"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"go.uber.org/zap"
)

//go:embed _migrations/*.sql
var migrations embed.FS

var (
	selectFromIps = strings.Join([]string{
		"SELECT i.ip::text",
		"FROM network.ips AS i",
		"WHERE i.ip = $1",
	}[:], " ")
	insertIntoTraffic = strings.Join([]string{
		"INSERT INTO network.ips(",
		"  ip",
		")",
		"VALUES($1)",
		"ON CONFLICT ON CONSTRAINT ips_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoHostnames = strings.Join([]string{
		"INSERT INTO network.hostnames(",
		"  hostname",
		")",
		"VALUES($1)",
		"ON CONFLICT ON CONSTRAINT hostnames_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoIpsHostnames = strings.Join([]string{
		"INSERT INTO network.ips_hostnames(",
		"  ip, hostname",
		")",
		"VALUES($1, $2)",
		"ON CONFLICT ON CONSTRAINT ips_hostnames_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoLocations = strings.Join([]string{
		"INSERT INTO network.locations(",
		"  city, country",
		")",
		"VALUES($1, $2)",
		"ON CONFLICT ON CONSTRAINT locations_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoIpsLocations = strings.Join([]string{
		"INSERT INTO network.ips_locations(",
		"  ip, location_fk",
		")",
		"SELECT $1, id",
		"FROM network.locations",
		"WHERE city = $2",
		"  AND country = $3",
		"ON CONFLICT ON CONSTRAINT ips_locations_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoPorts = strings.Join([]string{
		"INSERT INTO network.ports(",
		"  port",
		")",
		"VALUES($1)",
		"ON CONFLICT ON CONSTRAINT ports_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoIpsPorts = strings.Join([]string{
		"INSERT INTO network.ips_ports(",
		"  ip, port",
		")",
		"VALUES($1, $2)",
		"ON CONFLICT ON CONSTRAINT ips_ports_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoIsps = strings.Join([]string{
		"INSERT INTO network.isps(",
		"  isp",
		")",
		"VALUES($1)",
		"ON CONFLICT ON CONSTRAINT isps_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoIpsIsps = strings.Join([]string{
		"INSERT INTO network.ips_isps(",
		"  ip, isp",
		")",
		"VALUES($1, $2)",
		"ON CONFLICT ON CONSTRAINT ips_isps_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoVulns = strings.Join([]string{
		"INSERT INTO network.vulns(",
		"  type",
		")",
		"VALUES($1)",
		"ON CONFLICT ON CONSTRAINT vulns_pkey",
		"DO NOTHING",
	}[:], " ")
	insertIntoIpsVulns = strings.Join([]string{
		"INSERT INTO network.ips_vulns(",
		"  ip, type",
		")",
		"VALUES($1, $2)",
		"ON CONFLICT ON CONSTRAINT ips_vulns_pkey",
		"DO NOTHING",
	}[:], " ")
)

type PostgresqlConfigurations struct {
	Administrator         *string
	AdministratorPassword *string
	Host                  *string
	Username              *string
	Password              *string
	Database              *string
	Threads               *int
	ApplicationName       string
}

type MetaResult struct {
	Hostnames       []string
	Isp             *string
	City            *string
	Country         *string
	Organization    *string
	Ports           *[]int
	Vulnerabilities *[]string
}

type Model struct {
	logger          *zap.SugaredLogger
	keepAliveTicker *time.Ticker
	keepAliveDone   chan bool

	connectionString         string
	postgresqlConfigurations *PostgresqlConfigurations
	pool                     *pgxpool.Pool
	txOpts                   *pgx.TxOptions
}

func setupDatabase(username, password, database string) (string, error) {

	//TODO sanitize
	sqlComment := "--"
	if strings.Contains(username, sqlComment) ||
		strings.Contains(password, sqlComment) ||
		strings.Contains(database, sqlComment) {
		return " ", errors.New("invalid characters in username, password or database")
	}

	return strings.Join([]string{
		"DO",
		"$do$",
		"BEGIN",
		"  IF (",
		"    SELECT COUNT(*)",
		"    FROM pg_catalog.pg_user",
		"    WHERE usename = '" + username + "'",
		"  ) = 0 THEN",
		"    CREATE ROLE \"" + username + "\" LOGIN PASSWORD '" + password + "';",
		"  END IF;",
		"END",
		"$do$;",
		"CREATE SCHEMA IF NOT EXISTS network AUTHORIZATION \"" + username + "\";",
		"GRANT CONNECT ON DATABASE \"" + database + "\" TO \"" + username + "\";",
		"GRANT USAGE ON ALL SEQUENCES IN SCHEMA network TO \"" + username + "\";",
		"GRANT CREATE ON SCHEMA network TO \"" + username + "\";",
		"GRANT SELECT, INSERT, UPDATE, REFERENCES ON ALL TABLES IN SCHEMA network TO \"" + username + "\";",
		"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO \"" + username + "\";",
		"GRANT USAGE ON SCHEMA public TO \"" + username + "\";",
		"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA network TO \"" + username + "\";",
		"GRANT USAGE ON SCHEMA network TO \"" + username + "\";",
	}[:], " "), nil
}

func (m *Model) migrate(ctx context.Context) error {
	adminConn, err := pgx.Connect(ctx, fmt.Sprintf(strings.Join([]string{
		"postgres://%s:%s@%s:5432/%s?",
		"application_name=%s",
		"&connect_timeout=20",
	}[:], ""),
		*m.postgresqlConfigurations.Administrator,
		*m.postgresqlConfigurations.AdministratorPassword,
		*m.postgresqlConfigurations.Host,
		*m.postgresqlConfigurations.Database,
		m.postgresqlConfigurations.ApplicationName+"-admin",
	))
	if err != nil {
		return err
	}

	defer adminConn.Close(ctx)

	sourceInstance, err := httpfs.New(http.FS(migrations), "_migrations")
	if err != nil {
		return err
	}
	migrator, err := migrate.NewWithSourceInstance("httpfs", sourceInstance, fmt.Sprintf(strings.Join([]string{
		"postgres://%s:%s@%s:5432/%s?",
		"application_name=%s",
		"&connect_timeout=20",
		"&sslmode=disable",
	}[:], ""),
		*m.postgresqlConfigurations.Administrator,
		*m.postgresqlConfigurations.AdministratorPassword,
		*m.postgresqlConfigurations.Host,
		*m.postgresqlConfigurations.Database,
		m.postgresqlConfigurations.ApplicationName,
	))
	if err != nil {
		return err
	}

	setupDatabaseStr, err := setupDatabase(*m.postgresqlConfigurations.Username,
		*m.postgresqlConfigurations.Password, *m.postgresqlConfigurations.Database)
	if err != nil {
		return err
	}

	_, err = adminConn.Exec(ctx, setupDatabaseStr)
	if err != nil {
		return err
	}

	if err := migrator.Up(); errors.Is(err, migrate.ErrNoChange) {
		m.logger.Info(err)
	} else if err != nil {

		return err
	}

	sourceErr, databaseErr := migrator.Close()
	if sourceErr != nil {
		return sourceErr
	}

	if databaseErr != nil {
		return databaseErr
	}

	return nil
}

func New(logger *zap.SugaredLogger, ctx context.Context, postgresqlConfigurations *PostgresqlConfigurations) (*Model, error) {
	toReturn := &Model{
		postgresqlConfigurations: postgresqlConfigurations,
		connectionString: fmt.Sprintf(strings.Join([]string{
			"postgres://%s:%s@%s:5432/%s?",
			"application_name=%s",
			"&connect_timeout=20",
			"&pool_max_conns=%d",
			"&pool_min_conns=%d",
		}[:], ""),
			*postgresqlConfigurations.Username,
			*postgresqlConfigurations.Password,
			*postgresqlConfigurations.Host,
			*postgresqlConfigurations.Database,
			postgresqlConfigurations.ApplicationName,
			*postgresqlConfigurations.Threads,
			*postgresqlConfigurations.Threads,
		),
		txOpts: &pgx.TxOptions{
			IsoLevel:       pgx.ReadUncommitted,
			DeferrableMode: pgx.NotDeferrable,
			AccessMode:     pgx.ReadWrite,
		},
		logger: logger,
	}

	if err := toReturn.migrate(ctx); err != nil {
		return nil, err
	}

	if err := toReturn.initPool(ctx); err != nil {
		return nil, err
	}

	return toReturn, nil
}

func (model *Model) Dispose() {
	model.keepAliveDone <- true
	model.keepAliveTicker.Stop()
}

func (model *Model) keepAlive() {
	for {
		select {
		case <-model.keepAliveDone:
			return
		case _ = <-model.keepAliveTicker.C:
			err := model.pool.Ping(context.Background())

			if err != nil {

				panic(err)
			}

			model.logger.Debug("connected to postgresql")
		}
	}
}

func (model *Model) initPool(ctx context.Context) error {
	pool, err := pgxpool.Connect(ctx, model.connectionString)
	if err != nil {
		return err
	}

	model.pool = pool
	model.keepAliveTicker = time.NewTicker(time.Minute)
	model.keepAliveDone = make(chan bool)
	go model.keepAlive()
	return nil
}

func (model *Model) Exists(ctx context.Context, ip string) (bool, error) {
	var theIp string
	err := model.pool.QueryRow(ctx, selectFromIps, ip).Scan(&theIp)
	if err != nil && err.Error() == "no rows in result set" {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	if strings.EqualFold(theIp, ip) {
		return true, nil
	}

	return false, nil
}

func (model *Model) Store(ctx context.Context, ip string, metaResult *MetaResult) error {
	tx, err := model.pool.BeginTx(ctx, *model.txOpts)
	if err != nil {

		return err
	}

	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, insertIntoTraffic, ip); err != nil {

		return err
	}

	if metaResult != nil {
		if metaResult.Hostnames != nil {
			for _, anHostname := range metaResult.Hostnames {
				if _, err := tx.Exec(ctx, insertIntoHostnames, anHostname); err != nil {

					return err
				}

				if _, err := tx.Exec(ctx, insertIntoIpsHostnames, ip, anHostname); err != nil {

					return err
				}
			}
		}

		if metaResult.City != nil && metaResult.Country != nil {
			if _, err := tx.Exec(ctx, insertIntoLocations, *metaResult.City, *metaResult.Country); err != nil {

				return err
			}

			if _, err := tx.Exec(ctx, insertIntoIpsLocations, ip, *metaResult.City, *metaResult.Country); err != nil {

				return err
			}
		} else {

			model.logger.Debug("Could not insert location")
		}

		if metaResult.Ports != nil {
			for _, aPort := range *metaResult.Ports {
				if _, err := tx.Exec(ctx, insertIntoPorts, aPort); err != nil {

					return err
				}

				if _, err := tx.Exec(ctx, insertIntoIpsPorts, ip, aPort); err != nil {

					return err
				}
			}
		} else {

			model.logger.Debug("Could not insert ports")
		}

		if metaResult.Isp != nil {
			if _, err := tx.Exec(ctx, insertIntoIsps, *metaResult.Isp); err != nil {

				return err
			}

			if _, err := tx.Exec(ctx, insertIntoIpsIsps, ip, *metaResult.Isp); err != nil {

				return err
			}
		} else {

			model.logger.Debug("Could not insert isp")
		}

		if metaResult.Vulnerabilities != nil {
			for _, aVuln := range *metaResult.Vulnerabilities {
				if _, err := tx.Exec(ctx, insertIntoVulns, aVuln); err != nil {

					return err
				}

				if _, err := tx.Exec(ctx, insertIntoIpsVulns, ip, aVuln); err != nil {

					return err
				}
			}
		} else {

			model.logger.Debug("Could not insert vulnerabilities")
		}
	} else {

		model.logger.Warnf("No info about %s", ip)
	}

	tx.Commit(ctx)
	return nil
}
