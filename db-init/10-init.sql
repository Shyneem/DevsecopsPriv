CREATE DATABASE sonarqube;

-- Crear hypertable para wazuh_vulnerabilities (ejecutar después de crear la tabla)
\c vulnerabilidades_db;
-- Crear hypertable con columna de tiempo: detected_at
SELECT create_hypertable('wazuh_vulnerabilities', 'detected_at', chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);

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
SELECT add_compression_policy('wazuh_vulnerabilities', AFTER => INTERVAL '7 days', if_not_exists => TRUE);
