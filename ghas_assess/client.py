"""
Minimal, strictly read-only GitHub REST API client.

Design choices:
- Only GET requests are ever issued. There is no code path that writes.
- Handles pagination via Link headers.
- Handles secondary/primary rate limits with polite backoff.
- Tolerates 403/404 per-endpoint (feature disabled / no permission) by returning
  a sentinel so the assessor can record UNKNOWN rather than crash.
- Works against github.com and GitHub Enterprise (configurable api_url).
"""
import time
import json
import urllib.request
import urllib.error


class GitHubError(Exception):
    pass


class ForbiddenOrMissing(Exception):
    """Raised for 403/404 so callers can degrade gracefully to UNKNOWN."""
    def __init__(self, status, url, message=""):
        self.status = status
        self.url = url
        super().__init__(f"{status} for {url}: {message}")


class GitHubClient:
    def __init__(self, token, api_url="https://api.github.com", verbose=False):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.verbose = verbose

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ghas-assess/1.0",
        }

    def _request(self, url):
        if url.startswith("/"):
            url = self.api_url + url
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        for attempt in range(5):
            try:
                if self.verbose:
                    print(f"  GET {url}")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = resp.read().decode("utf-8")
                    data = json.loads(body) if body else None
                    return data, dict(resp.headers)
            except urllib.error.HTTPError as e:
                # Rate limiting
                if e.code in (403, 429):
                    remaining = e.headers.get("X-RateLimit-Remaining")
                    reset = e.headers.get("X-RateLimit-Reset")
                    retry_after = e.headers.get("Retry-After")
                    if retry_after:
                        wait = int(retry_after)
                        if self.verbose:
                            print(f"  rate limited; sleeping {wait}s")
                        time.sleep(min(wait, 60))
                        continue
                    if remaining == "0" and reset:
                        wait = max(0, int(reset) - int(time.time())) + 1
                        if wait <= 90:
                            if self.verbose:
                                print(f"  primary rate limit; sleeping {wait}s")
                            time.sleep(wait)
                            continue
                    # Otherwise it's a genuine permission/feature-off 403
                    raise ForbiddenOrMissing(e.code, url, e.read().decode("utf-8", "ignore"))
                if e.code == 404:
                    raise ForbiddenOrMissing(404, url, "not found")
                if e.code >= 500:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise GitHubError(f"HTTP {e.code} for {url}: {e.read().decode('utf-8','ignore')}")
            except urllib.error.URLError as e:
                time.sleep(2 * (attempt + 1))
                last = e
        raise GitHubError(f"Request failed after retries: {url}")

    def get(self, url):
        """Single object GET. Returns parsed JSON or raises ForbiddenOrMissing."""
        data, _ = self._request(url)
        return data

    def paginate(self, url, per_page=100):
        """Yield items across all pages of a list endpoint."""
        sep = "&" if "?" in url else "?"
        next_url = f"{url}{sep}per_page={per_page}"
        while next_url:
            data, headers = self._request(next_url)
            if isinstance(data, dict):
                # some endpoints wrap lists (e.g. {'repositories': [...]})
                for key in ("repositories", "items", "configurations"):
                    if key in data:
                        data = data[key]
                        break
            if not data:
                break
            for item in data:
                yield item
            next_url = self._next_link(headers.get("Link", ""))

    @staticmethod
    def _next_link(link_header):
        if not link_header:
            return None
        for part in link_header.split(","):
            section = part.split(";")
            if len(section) < 2:
                continue
            url = section[0].strip().lstrip("<").rstrip(">")
            rel = section[1].strip()
            if rel == 'rel="next"':
                return url
        return None

    def check_token(self):
        """Return the authenticated login, or raise."""
        data = self.get("/user")
        return data.get("login") if data else None
