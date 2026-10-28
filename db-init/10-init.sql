-- Crear base de datos auxiliar para sonarqube de forma segura
SELECT 'CREATE DATABASE sonarqube'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sonarqube')\gexec

-- Conectar a la base de datos principal de la aplicación
\c vulnerabilidades_db;

-- Habilitar extensión TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Configuración de Hypertable, índices y compresión sobre wazuh_vulnerabilities
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'wazuh_vulnerabilities') THEN
        -- Ajustar claves para permitir particionamiento por detected_at si no es hypertable aún
        IF NOT EXISTS (SELECT FROM timescaledb_information.hypertables WHERE hypertable_name = 'wazuh_vulnerabilities') THEN
            ALTER TABLE vulnerability_history DROP CONSTRAINT IF EXISTS vulnerability_history_vulnerability_id_fkey;
            ALTER TABLE wazuh_vulnerabilities DROP CONSTRAINT IF EXISTS uniq_wazuh_vuln;
            ALTER TABLE wazuh_vulnerabilities DROP CONSTRAINT IF EXISTS wazuh_vulnerabilities_pkey;
            ALTER TABLE wazuh_vulnerabilities ADD PRIMARY KEY (id, detected_at);
            ALTER TABLE wazuh_vulnerabilities ADD CONSTRAINT uniq_wazuh_vuln UNIQUE (connection_id, agent_id, package_name, package_version, cve_id, detected_at);

            PERFORM create_hypertable('wazuh_vulnerabilities', 'detected_at', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE, migrate_data => TRUE);
        END IF;

        -- Índices para acelerar filtros y ordenamientos frecuentes
        CREATE INDEX IF NOT EXISTS idx_wazuh_vuln_first_seen ON wazuh_vulnerabilities (first_seen);
        CREATE INDEX IF NOT EXISTS idx_wazuh_vuln_last_seen ON wazuh_vulnerabilities (last_seen);
        CREATE INDEX IF NOT EXISTS idx_wazuh_vuln_agent_id ON wazuh_vulnerabilities (agent_id);
        CREATE INDEX IF NOT EXISTS idx_wazuh_vuln_cve_id ON wazuh_vulnerabilities (cve_id);
        CREATE INDEX IF NOT EXISTS idx_wazuh_vuln_package_name ON wazuh_vulnerabilities (package_name);
        CREATE INDEX IF NOT EXISTS idx_wazuh_vuln_severity ON wazuh_vulnerabilities (severity);
        CREATE INDEX IF NOT EXISTS idx_wazuh_vuln_status ON wazuh_vulnerabilities (status);

        -- Compresión automática para datos históricos (mayores a 7 días)
        ALTER TABLE wazuh_vulnerabilities SET (
            timescaledb.compress,
            timescaledb.compress_orderby = 'detected_at DESC'
        );
        PERFORM add_compression_policy('wazuh_vulnerabilities', compress_after => INTERVAL '7 days', if_not_exists => TRUE);
    END IF;
END $$;
