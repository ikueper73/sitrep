-- Per-CVE data from enrichment sources (EPSS, NVD), joined into the briefing by CVE ID.
CREATE TABLE cve_enrichment (
  cve                   TEXT PRIMARY KEY,
  -- FIRST EPSS: probability of exploitation in the next 30 days, and its percentile
  epss                  REAL,
  epss_percentile       REAL,
  epss_date             TEXT,                 -- date of the EPSS model run
  epss_checked_at       TEXT,
  -- NVD: one chosen CVSS metric (see src/enrich/nvd.ts for the preference order)
  cvss_score            REAL,
  cvss_severity         TEXT,                 -- critical | high | medium | low | none
  cvss_version          TEXT,
  cvss_vector           TEXT,
  cvss_source           TEXT,                 -- "nvd" or the CNA that scored it
  -- CISA SSVC decision points, published through NVD
  ssvc_exploitation     TEXT,
  ssvc_automatable      TEXT,
  ssvc_technical_impact TEXT,
  nvd_status            TEXT,                 -- e.g. Analyzed, Awaiting Analysis; NULL if NVD has no record
  nvd_checked_at        TEXT
);
