# Deployment – projects.bluecherlab.com

Static site for Cloudflare Pages. Build output directory: `website/`

## Cloudflare Pages Setup

1. **Create project** in Cloudflare Dashboard → Pages → Create a project
2. **Connect Git** repository or use Direct Upload
3. **Build settings**:
   - Build command: *(leave empty – no build step)*
   - Build output directory: `website`
   - Root directory: `/` (repo root)
4. **Custom domain**: Add `projects.bluecherlab.com` under Settings → Custom domains
   - Add a CNAME record: `projects` → `<your-pages-project>.pages.dev`

## Direct Upload (no CI)

```bash
# Install Wrangler
npm install -g wrangler

# Deploy
wrangler pages deploy website --project-name=bluecherlab-projects
```

## URL Structure

| URL | File |
|-----|------|
| `projects.bluecherlab.com/` | `website/index.html` (redirects to `/wakefromfar/`) |
| `projects.bluecherlab.com/wakefromfar/` | `website/wakefromfar/index.html` |
| `projects.bluecherlab.com/wakefromfar/privacy` | `website/wakefromfar/privacy.html` |
| `projects.bluecherlab.com/wakefromfar/imprint` | `website/wakefromfar/imprint.html` |

## TODO before going live

- [ ] Replace `href="#"` in `index.html` → real App Store URL (iOS)
- [ ] Replace `href="#"` in `index.html` → real Play Store URL (Android)
- [ ] Replace `href="#"` in `index.html` (GitHub button) → real GitHub repo URL
- [ ] Verify Impressum details are still current
- [ ] Review Privacy Policy if analytics are added later
