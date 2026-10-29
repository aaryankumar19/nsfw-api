# ==============================================================================
# FILE: README.md
# DESCRIPTION: Architecture, deployment, API documentation, and Android guide
#              for the Mindful NSFW Blocklist API on Cloudflare Pages.
# ==============================================================================

# NSFW Blocklist API

A high-performance, versioned static blocklist API hosted on **Cloudflare Pages** with zero runtime database, server-side functions (FastAPI/Django), or Docker overhead. Release assets are generated through Python, stored statically at the Cloudflare edge, protected by API secret key authentication via Cloudflare Pages middleware, and consumed resiliently by the Mindful Android client.

---

## 1. Architecture Overview

```
                      +-----------------------------+
                      |       data/domains.txt      |  <-- Source of Truth (1 domain/line)
                      +--------------+--------------+
                                     |
                                     v
                       python3 scripts/build.py (--bump / --rollback)
                                     |
                     +---------------+---------------+
                     |                               |
                     v                               v
    public/api/v1/releases/N.json        public/api/v1/version.json
    (Immutable Release Snapshot)         (Active Version Metadata + SHA256)
                     |                               |
                     +---------------+---------------+
                                     |
                               Git Push
                                     |
                                     v
                          Cloudflare Pages Host
                                     |
            functions/api/v1/_middleware.js (API Key Auth & CORS)
                                     |
                                     v
                             Android Client
         (Local SQLite / File Cache + Atomic Replacement via WorkManager)
```

### Key Guarantees
- **Zero API Dependency for Blocking:** Website blocking on Android never fails if the API is offline. The app always uses its local validated list.
- **Immutable Releases:** Old snapshots (`releases/1.json`, `releases/2.json`) are never overwritten. Rollbacks point `version.json` back without altering history.
- **Payload Integrity:** Every release has its raw bytes hashed via SHA-256, verified on Android before activation.
- **Edge Caching:** `releases/*.json` are cached with `Cache-Control: public, max-age=31536000, immutable`, while `version.json` revalidates fast (`max-age=60`).
- **Timing-Safe Auth:** API requests require a shared secret key, verified via constant-time comparison in Cloudflare Pages middleware.

---

## 2. Directory Structure

```
nsfw-api/
├── public/
│   └── api/
│       └── v1/
│           ├── version.json           # Small metadata file polled by Android for updates
│           ├── domains.json           # Convenience copy of the latest active release
│           └── releases/
│               ├── 1.json             # Immutable snapshot of release 1
│               └── 2.json             # Immutable snapshot of release 2
├── data/
│   ├── domains.txt                    # Editable source of truth; one domain per line
│   └── metadata.json                  # Internal tracking for active schema & release versions
├── functions/
│   └── api/
│       └── v1/
│           └── _middleware.js         # Cloudflare Pages edge auth & CORS middleware
├── scripts/
│   ├── build.py                       # Domain validator, release generator & hasher
│   └── test_api.sh                    # Automated end-to-end API test suite
├── .env.example                       # Environment configuration guide
├── .env                               # Local secrets (git-ignored)
├── .gitignore                         # Exclusions for build artifacts and secrets
├── package.json                       # Convenient npm commands for Wrangler and build
└── README.md                          # System documentation
```

---

## 3. API Endpoints Specification

All endpoints are hosted under `/api/v1/` and require authentication.

### Authentication
Requests must supply the secret key defined in Cloudflare Pages environment variables (`API_SECRET_KEY`). Three methods are supported:

| Method | Syntax |
|---|---|
| **Header (Recommended)** | `Authorization: Bearer <API_SECRET_KEY>` |
| **Custom Header** | `X-API-Key: <API_SECRET_KEY>` |
| **Query Parameter** | `?key=<API_SECRET_KEY>` or `?api_key=<API_SECRET_KEY>` |

---

### Endpoint 1: Active Version Metadata
`GET /api/v1/version.json`

Polled periodically by the Android client to detect new releases without downloading the full blocklist.

**Request:**
```bash
curl -H "X-API-Key: your-secret-key" https://your-project.pages.dev/api/v1/version.json
```

**Response (HTTP 200 OK):**
```json
{
  "schema_version": 1,
  "domains_version": 1,
  "domains_url": "/api/v1/releases/1.json",
  "sha256": "<release-sha256-hash>",
  "updated_at": "2026-10-29T03:24:07Z"
}
```

---

### Endpoint 2: Immutable Versioned Release
`GET /api/v1/releases/{version}.json`

Returns the complete domain list for release `{version}`. Once deployed, release snapshots are **immutable** and never modified.

**Request:**
```bash
curl -H "Authorization: Bearer your-secret-key" https://your-project.pages.dev/api/v1/releases/1.json
```

**Response (HTTP 200 OK):**
```json
{
  "schema_version": 1,
  "version": 1,
  "domains": [
    "another-nsfw.example",
    "example-nsfw.com",
    "restricted-preview.test",
    "sample-adult-content.org",
    "test-explicit-media.net"
  ]
}
```

---

### Endpoint 3: Latest Release Alias
`GET /api/v1/domains.json`

Convenience alias containing identical content to the currently active release. (For the Android client, use the versioned URL from `version.json` to leverage immutable caching).

**Request:**
```bash
curl "https://your-project.pages.dev/api/v1/domains.json?key=your-secret-key"
```

---

## 4. Release & Update Workflow

### Step 1: Update the Blocklist
Edit `data/domains.txt` to add, update, or remove domains.
- Supports both exact hostnames (`example.com`) and wildcard subdomains (`*.example.com`).
- URLs (`https://site.com/path`), ports (`site.com:8080`), and queries are automatically stripped.
- Comments starting with `#` and blank lines are ignored.

### Step 2: Build the New Release
Run the build script with `--bump`:
```bash
python3 scripts/build.py --bump
```
This automatically:
1. Normalizes and validates all domains against RFC 1035/1123 hostname standards.
2. Deduplicates and alphabetically sorts the domain list.
3. Creates a new immutable release file: `public/api/v1/releases/<new_version>.json`.
4. Computes the raw SHA-256 checksum.
5. Updates `public/api/v1/domains.json` and `public/api/v1/version.json`.

### Step 3: Commit and Push
```bash
git add .
git commit -m "release: bump domains to version 3"
git push origin main
```
Cloudflare Pages automatically detects the Git push, deploys the new static files and middleware to the edge globally within seconds.

---

## 5. Instant Rollback Procedure

If a published release (e.g. version 3) turns out to have problematic domains, you can roll back instantly **without deleting or mutating history**:

```bash
# Point version.json back to version 2
python3 scripts/build.py --rollback 2

git add public/ data/
git commit -m "rollback: revert active release to version 2"
git push origin main
```
- The Android apps will see `domains_version: 2` on their next check and revert immediately.
- The faulty release `releases/3.json` remains immutable on disk, preserving full auditability.

---

## 6. Cloudflare Pages Deployment Setup

1. **Create Repository:**
   Push this repository to GitHub or GitLab.

2. **Connect to Cloudflare Pages:**
   - Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) -> **Workers & Pages** -> **Create application** -> **Pages** -> **Connect to Git**.
   - Select your `nsfw-api` repository.

3. **Configure Build Settings:**
   - **Framework preset:** None
   - **Build command:** `python3 scripts/build.py`
   - **Build output directory:** `public`

4. **Set Secret Key Environment Variable:**
   - Under **Settings** -> **Environment variables** (for both Production and Preview):
     - Variable name: `API_SECRET_KEY`
     - Value: `<your-strong-random-secret-key>`

Cloudflare Pages automatically mounts `functions/api/v1/_middleware.js` to protect your endpoints.

---

## 7. Local Development & Testing

### Run Local Dev Server
```bash
# Starts Wrangler dev server on http://localhost:8788 with test secret key
npm run dev
```

### Run Automated Test Suite
```bash
# Runs the full verification suite testing 401s, 200s, CORS, headers, and SHA256 integrity
npm test
```

---

## 8. Android Client Implementation Guide

The Android implementation follows four strict principles:
1. **Never block user browsing on network latency.**
2. **Atomic file replacement** prevents corrupt state if interrupted.
3. **SHA-256 verification** ensures corrupt downloads are never activated.
4. **WorkManager periodic task** checks every 12–24 hours when Wi-Fi is available.

### Kotlin WorkManager Example

```kotlin
package com.mindful.app.blocklist

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

class BlocklistSyncWorker(
    private val context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    private val client = OkHttpClient()
    private val prefs = context.getSharedPreferences("blocklist_prefs", Context.MODE_PRIVATE)

    companion object {
        private const val BASE_URL = "https://your-project.pages.dev"
        private const val API_SECRET_KEY = "your-secure-secret-key-here"
        const val ACTIVE_BLOCKLIST_FILENAME = "active_domains.json"
    }

    override suspend fun doWork(): Result {
        return try {
            // 1. Fetch version metadata
            val versionRequest = Request.Builder()
                .url("$BASE_URL/api/v1/version.json")
                .header("X-API-Key", API_SECRET_KEY)
                .build()

            val versionResponse = client.newCall(versionRequest).execute()
            if (!versionResponse.isSuccessful) return Result.retry()

            val versionJson = JSONObject(versionResponse.body!!.string())
            val remoteVersion = versionJson.getInt("domains_version")
            val releaseUrl = versionJson.getString("domains_url")
            val expectedSha256 = versionJson.getString("sha256")

            val localVersion = prefs.getInt("local_domains_version", 0)

            // If already up to date, skip downloading full release
            if (remoteVersion == localVersion && getActiveBlocklistFile().exists()) {
                return Result.success()
            }

            // 2. Download release into a temporary file
            val tempFile = File(context.cacheDir, "release_${remoteVersion}.tmp")
            val releaseRequest = Request.Builder()
                .url("$BASE_URL$releaseUrl")
                .header("X-API-Key", API_SECRET_KEY)
                .build()

            val releaseResponse = client.newCall(releaseRequest).execute()
            if (!releaseResponse.isSuccessful) return Result.retry()

            val releaseBytes = releaseResponse.body!!.bytes()
            FileOutputStream(tempFile).use { it.write(releaseBytes) }

            // 3. Compute and verify SHA-256 checksum
            val digest = MessageDigest.getInstance("SHA-256")
            val calculatedSha256 = digest.digest(releaseBytes).joinToString("") { "%02x".format(it) }

            if (!calculatedSha256.equals(expectedSha256, ignoreCase = true)) {
                tempFile.delete()
                return Result.retry() // Checksum mismatch, do not activate
            }

            // 4. Validate JSON structure before activating
            val releaseJson = JSONObject(String(releaseBytes, Charsets.UTF_8))
            val domainsArray = releaseJson.getJSONArray("domains")
            if (domainsArray.length() == 0) {
                tempFile.delete()
                return Result.failure()
            }

            // 5. Atomically replace the active blocklist file
            val targetFile = getActiveBlocklistFile()
            if (tempFile.renameTo(targetFile)) {
                prefs.edit().putInt("local_domains_version", remoteVersion).apply()
            } else {
                targetFile.delete()
                tempFile.renameTo(targetFile)
                prefs.edit().putInt("local_domains_version", remoteVersion).apply()
            }

            Result.success()
        } catch (e: Exception) {
            // On network or IO failure, existing local active_domains.json continues working
            Result.retry()
        }
    }

    private fun getActiveBlocklistFile(): File {
        return File(context.filesDir, ACTIVE_BLOCKLIST_FILENAME)
    }
}
```

---

## 9. Security & Privacy Notes

- The API is strictly read-only and static; only repository collaborators with Git push permissions can release updates.
- API keys protect against unauthorized automated scraping and usage beyond your Mindful Android application.
- SHA-256 hashes detect data corruption or proxy tampering before any domain is added to Android device filtering.
