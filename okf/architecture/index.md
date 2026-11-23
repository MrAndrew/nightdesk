# Architecture

* [System architecture](system.md) - Processes, components and data flow.
* [Web client](web-client.md) - Shell, panel and view contracts, global state and live topics.
* [Phone layout](phone.md) - The v1.2 phone contract (pages and Back, the bottom layer, sheets, swipes, libraries on demand) and each view on a phone.
* [HTTP API](api.md) - Every backend endpoint.
* [Local AI, vectors and search](local-ai.md) - The MLX helper, the AI client, the Qdrant/DuckDB vector index, the embedding pipeline, hybrid search and offline mode.
* [Routing watch](routing-watch.md) - What v1.2 built for the per-network BGP watch: the watchlist, sources, detection and cards.
* [Notes and Copy summary](notes.md) - Server-side notes on incidents, entities, stories and articles, and the redacting Copy-summary builder.
* [Notifications](notifications.md) - The opt-in webhook (ntfy, Gotify, Home Assistant, Discord-compatible, plain JSON): triggers, destination checks, offline, delivery log.
* [My stack](my-stack.md) - "What you follow": vendors, products, entities and keywords matched across the data.
* [Help desk](help.md) - The "?" help desk, its sections, the glossary and shortcuts.
* [Watch](watch.md) - The Watch landing page and the shared last-seen marker.
* [Testing and the E2E journeys](testing.md) - The pytest suite, the end-to-end journeys in tests/e2e, the smoke/deeplinks scripts and the merge gate.
* [Deployment](deployment.md) - The one-line Docker install (HTTPS by Caddy), home server, and running with uv.
