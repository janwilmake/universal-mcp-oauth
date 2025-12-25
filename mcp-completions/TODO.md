Check [readme](https://github.com/janwilmake/universal-mcp-oauth/tree/main/mcp-completions).

- ✅ Intended usage: **package**
- ✅ Add shadow url object replacer such that github.com works
- ✅ Add extract url such that any other html/pdf response works with that as fallback
- ✅ ensure additional cost for extract and other apis gets properly added to chat completions usage cost

After this; how can I add statefulness and other cool features?

- cache?
- og image and view of response
- frontmatter
- responses api
- x login + stripe credit? pricing
- cronjobs

Where does the CLI hook into the boundary of what i'm creating? Determine how I add `mcp-completions` into `contextarea` as well as the new `nlang.dev` cli
