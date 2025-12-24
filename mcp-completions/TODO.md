Check [readme](https://github.com/janwilmake/universal-mcp-oauth/tree/main/enhanced-chatcompletions).

- Intended usage: package or hosted? likely package because of additional cost.
- Add shadow url object replacer such that github.com works
- Add extract url such that any other html/pdf response works with that as fallback
- ensure additional cost for extract and other apis gets properly added to chat completions usage cost

After this; how can I add statefulness?

- cache?
- x login + stripe credit? pricing

Determine how I add `mcp-completions` into `contextarea`...
