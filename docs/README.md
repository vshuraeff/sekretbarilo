# Docs site

This directory is a Jekyll site published to GitHub Pages. `_config.yml` sets
`baseurl: "/sekretbarilo"`, so every internal link and asset path is relative
to that prefix, and a local build has to account for it too.

## Building the docs locally

The `Gemfile` here pulls in the `github-pages` gem, which pins Jekyll and every
plugin GitHub Pages actually runs. That gem's own dependency pins lag behind
current Ruby releases, so `bundle install` against it can fail to resolve or
compile native extensions on a newly installed Ruby. If that happens, build
with a scratch Gemfile instead of trying to make the `github-pages` gem
install:

1. Create a Gemfile *outside* this repository (any scratch directory works),
   pinned to the Jekyll 3.x line the `github-pages` gem currently ships, plus
   the plugins and standard-library gems this site's `_config.yml` and Ruby
   version need:

   ```ruby
   # Gemfile (outside the repo)
   source "https://rubygems.org"

   gem "jekyll", "~> 3.10"
   gem "kramdown-parser-gfm"
   gem "jekyll-seo-tag"
   gem "jekyll-sitemap"
   gem "rouge"
   gem "csv"
   gem "base64"
   gem "bigdecimal"
   gem "logger"
   gem "webrick"
   ```

2. Install into that scratch directory rather than the repo, then build with
   `-s` pointed at this `docs/` directory and `-d` at a scratch output
   directory. Run the build with its working directory set to the scratch
   Gemfile's directory, not this repo: Jekyll writes a `.sass-cache` into its
   current directory, and that cache does not belong in the repo checkout.

   ```sh
   cd /path/to/scratch-dir
   BUNDLE_GEMFILE=/path/to/scratch-dir/Gemfile BUNDLE_PATH=/path/to/scratch-dir/vendor \
     bundle install
   BUNDLE_GEMFILE=/path/to/scratch-dir/Gemfile BUNDLE_PATH=/path/to/scratch-dir/vendor \
     bundle exec jekyll build -s /path/to/repo/docs -d /path/to/scratch-dir/out
   ```

   `BUNDLE_PATH` has to be set on the `jekyll build` invocation too, not only
   on `bundle install`: it is an environment variable, not something
   `bundle install` persists on its own, and without it on the second command
   `bundle exec` looks for the gems in the default (non-scratch) location and
   fails to find them.

3. Serve the built output under the same `/sekretbarilo` prefix the site
   expects, for example by putting the built directory under a parent
   directory named `sekretbarilo` and serving from that parent:

   ```sh
   cd /path/to/scratch-dir
   mv out sekretbarilo
   ruby -run -e httpd . -p 8000
   ```

   `ruby -run -e httpd` needs the `webrick` gem (bundled above); on a Ruby
   build without it in the standard library it can fail with "webrick is not
   found". Any other static file server serving the same parent directory
   works just as well — the only requirement is that the built site is
   reachable under a `/sekretbarilo/` path segment, matching `baseurl`.

Verify the build with a fresh Ruby by checking its version first
(`ruby -v`) and confirming `bundle exec jekyll build` exits cleanly with no
Liquid warnings — a literal `{{ }}` or `${{ }}` in Markdown text needs
`{% raw %}...{% endraw %}` around it, or Jekyll's Liquid parser errors on it
as `[:end_of_string] is not a valid expression`.
