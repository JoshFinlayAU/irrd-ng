# GraphiQL explorer files

These are the files IRRd 4.5.4 serves under `/static/js/graphiql/` for its GraphQL explorer page. irrd-ng embeds them in the binary (`src/static_files.rs`) and serves them at the same paths. They are byte-identical copies of `irrd/webui/static/js/graphiql/` at the pinned v4 tag, kept here so that irrd-ng builds from a source tarball without the `vendor/irrd-v4` submodule. The test `graphiql_assets_match_vendor` in `src/static_files.rs` fails if a copy and the submodule ever disagree, and is skipped when the submodule is not checked out.

Do not edit or reformat these files. To change them, bump the v4 baseline and copy the new files from the submodule.

| File | Upstream origin | Licence |
|---|---|---|
| `react.production.min.js` | `react@18.3.1/umd/react.production.min.js` on npm | MIT, `licenses/react.txt` |
| `react-dom.production.min.js` | `react-dom@18.3.1/umd/react-dom.production.min.js` on npm | MIT, `licenses/react.txt` (react-dom ships the same text) |
| `graphiql.min.js` | `graphiql@3.9.0/graphiql.min.js` on npm | MIT, `licenses/graphiql.txt` |
| `graphiql.min.css` | `graphiql@3.9.0/graphiql.min.css` on npm | MIT, `licenses/graphiql.txt` |
| `plugin-explorer.umd.js` | `@graphiql/plugin-explorer@3.2.6/dist/index.umd.js` on npm | MIT, `licenses/graphiql-plugin-explorer.txt`; it bundles `graphiql-explorer` 0.9.0, MIT, `licenses/graphiql-explorer.txt` |
| `plugin-explorer.style.css` | `@graphiql/plugin-explorer@3.2.6/dist/style.css` on npm | MIT, `licenses/graphiql-plugin-explorer.txt` |
| `mount.js` | written for IRRd, adapted from GraphiQL's CDN example | IRRd's BSD-2-Clause, `licenses/irrd.txt` |
| `page.css` | written for IRRd, adapted from GraphiQL's CDN example | IRRd's BSD-2-Clause, `licenses/irrd.txt` |

The six npm files are the ones IRRd's `irrd/scripts/update_graphiql_vendor.py` downloads from unpkg, and each was checked to be byte-identical to the published package file. The page that loads them, `src/graphiql.html`, is IRRd's `irrd/server/graphql/graphiql.html` (BSD-2-Clause) and is covered by the same test.

The licence texts come from the published packages: `react@18.3.1/LICENSE`, `graphiql@3.9.0/LICENSE` and `graphiql-explorer@0.9.0/LICENSE`. The `@graphiql/plugin-explorer` package declares MIT but ships no licence file, so its text is the GraphiQL repository's `LICENSE` at the `@graphiql/plugin-explorer@3.2.6` tag. The minified bundles also keep the notices of the smaller packages they include (graphql-js and others), which are MIT as well.
