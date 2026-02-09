# WebShare - Claude Instructions

## Project Structure

- `src/` - All PHP source files (DocumentRoot on servers)
- `installer/` - Installation scripts (get-webshare.sh, install.sh)
- `release.sh` - Automated release script

## Releasing a New Version

When the user asks to release/push a new version, use `release.sh`:

### Steps:
1. Write the changelog to a temp file (markdown format, multi-line)
2. Run the release script with `--notes-file` and `--yes`

### Example:
```bash
# 1. Write changelog
cat > /tmp/release-notes.md << 'EOF'
### Chat Fixes
- **Feature name** - Description of what it does
  - Additional detail if needed
- **Another fix** - What was fixed

### Other Changes
- **Something else** - Description
EOF

# 2. Run release script (updates index.php, version.json, CHANGELOG.md, commits, pushes, creates GitHub release)
./release.sh 3.5.7 "Short one-line description" --notes-file /tmp/release-notes.md --yes
```

### What the script does automatically:
1. Updates `WEBSHARE_VERSION` in `src/index.php`
2. Updates `src/version.json` (version, date, changelog)
3. Adds new section to `src/CHANGELOG.md` + updates version table
4. `git add` + `commit` + `push`
5. Creates GitHub release with `gh release create`

### Important:
- Version format: `X.Y.Z` (e.g. 3.5.7)
- Short description goes to: commit message, version.json, release title
- Notes file content goes to: CHANGELOG.md section, GitHub release body
- Always commit code changes BEFORE running release.sh (it only adds version files)

## Live Update System

Servers update via `live-update.php` which downloads files one-by-one from:
- **Stable**: `https://raw.githubusercontent.com/toshko37/webshare/main/src/{file}`
- **Dev**: `https://webshare.techbg.net/{file}`

New PHP files must be added to the `$phpFiles` array in `src/live-update.php`.

## Dev Server

- Primary: https://webshare.techbg.net (this machine, /var/www/webshare/src/)
- Secondary: https://webshare2.techbg.net (user: koko, pass: 1q)
