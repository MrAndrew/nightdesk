"""News tables. Described in okf/data/news.md."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id            VARCHAR PRIMARY KEY,      -- sha1(normalised url)[:16]
    url           VARCHAR NOT NULL,
    source        VARCHAR,                  -- outlet label, e.g. 'The Record'
    title         VARCHAR,
    published     TIMESTAMPTZ,
    fetched_at    TIMESTAMPTZ,
    text          VARCHAR,
    html_path     VARCHAR,                  -- raw/articles/YYYY/MM/DD/<id>.html.gz
    story_id      VARCHAR,
    lang          VARCHAR,
    status        VARCHAR,                  -- queued | ok | blocked | failed | skipped
    source_id     VARCHAR,                  -- the batch source that listed it
    event_id      VARCHAR,
    tier          VARCHAR,
    role          VARCHAR,                  -- newsroom | research
    dek           VARCHAR,                  -- feed summary / meta description
    author        VARCHAR,
    canonical_url VARCHAR,
    links         VARCHAR[],                -- outbound links from the main text
    reason        VARCHAR,                  -- why blocked / failed / skipped
    http_status   INTEGER,
    etag          VARCHAR,
    last_modified VARCHAR,
    attempts      INTEGER DEFAULT 0,
    next_attempt  TIMESTAMPTZ,
    queued_at     TIMESTAMPTZ DEFAULT now(),
    minhash       UBIGINT[],
    dup_of        VARCHAR,                  -- syndicated / near-duplicate copy of this article id
    chunks        INTEGER,
    embedded_at   TIMESTAMPTZ,
    clustered_at  TIMESTAMPTZ,
    entities_at   TIMESTAMPTZ
);
ALTER TABLE articles ADD COLUMN IF NOT EXISTS sponsored VARCHAR;      -- why it is sponsored / promotional (kept out of stories)
ALTER TABLE articles ADD COLUMN IF NOT EXISTS checked_at TIMESTAMPTZ;  -- last conditional re-fetch
ALTER TABLE articles ADD COLUMN IF NOT EXISTS refetch_stage INTEGER DEFAULT 0;
ALTER TABLE articles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;  -- text changed on a re-fetch
ALTER TABLE articles ADD COLUMN IF NOT EXISTS tier_reason VARCHAR;
ALTER TABLE articles ADD COLUMN IF NOT EXISTS entities_llm_missed TIMESTAMPTZ;  -- entities extracted while the AI helper was down, revisited later
ALTER TABLE articles ADD COLUMN IF NOT EXISTS entities_llm_tries INTEGER;  -- LLM passes in a row that timed out or errored (backoff)
ALTER TABLE articles ADD COLUMN IF NOT EXISTS entities_fails INTEGER;      -- entity ingests in a row that raised (backoff)
ALTER TABLE articles ADD COLUMN IF NOT EXISTS entities_failed_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS article_chunks (
    article_id VARCHAR,
    idx        INTEGER,
    text       VARCHAR,
    PRIMARY KEY (article_id, idx)
);
CREATE TABLE IF NOT EXISTS article_vecs (
    article_id VARCHAR PRIMARY KEY,         -- mean of the chunk embeddings, for clustering
    vec        FLOAT[]
);
CREATE TABLE IF NOT EXISTS stories (
    id            VARCHAR PRIMARY KEY,
    title         VARCHAR,
    summary       VARCHAR,
    summary_by    VARCHAR,                  -- llm | dek
    summary_n     INTEGER,                  -- article count when the summary was written
    lead_article  VARCHAR,
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    article_count INTEGER,
    source_count  INTEGER,                  -- distinct outlets, syndicated copies counted once
    tier_counts   JSON,                     -- {"A": n, "B": n, ...} distinct outlets per tier
    sources       VARCHAR[],
    top_entities  JSON,
    updated_at    TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS news_robots (
    domain     VARCHAR PRIMARY KEY,
    status     INTEGER,
    body       VARCHAR,
    fetched_at TIMESTAMPTZ
);
"""
