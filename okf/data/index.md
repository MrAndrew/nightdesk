# Data

* [Data architecture](architecture.md) - Lake layout, pipeline, enrichment, DuckDB loading and retention.
* [events table](events.md) - One row per distinct observation from any source.
* [Operational tables](operational-tables.md) - source_state, runs and metrics.
* [Event kinds](event-kinds.md) - Kinds, categories, display groups and producing sources.
* [Cyber Pulse index](cyber-pulse.md) - The composite risk score and its sub-indices.
* [Storage estimates](storage-estimates.md) - Disk needed for 30 days to 3 years of current and candidate sources.
* [Network logs](netlog.md) - Zeek log import, devices, threat indicator intervals, time-correct matching and alert severities.
* [Entities and claims](entities.md) - Entity, mention and claim tables, ATT&CK and MISP reference data, IOC and LLM extraction, event linking, confidence scoring and the entities API.
* [News articles and stories](news.md) - Feeds, the polite article fetcher, extraction, chunks and embeddings, story clustering, search and watchlists.
