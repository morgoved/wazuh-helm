"""Make every Wazuh node run the master's ruleset after a deployment.

Workers start analysisd before the cluster integrity sync delivers new rules and
decoders, and nothing reloads it afterwards, so they keep the previous ruleset.
This Job waits for the manager rollout and the sync, compares what analysisd has
loaded on each node with the master, and reloads the ruleset once if a node differs.

Runs with the manager image's bundled interpreter; stdlib only.
"""
import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__("HTTP %s: %s" % (status, body[:500]))
        self.status = status
        self.body = body


def _request(req, context):
    try:
        with urllib.request.urlopen(req, context=context, timeout=60) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as e:
        raise ApiError(e.code, e.read().decode(errors="replace"))
    except (urllib.error.URLError, OSError) as e:
        raise ApiError(0, str(e))


class WazuhApi:
    """Wazuh API client. The chart's API certificate is self-signed: not verified."""

    def __init__(self, base_url, user, password):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.token = None
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def _authenticate(self):
        req = urllib.request.Request(self.base_url + "/security/user/authenticate?raw=true", method="POST")
        creds = base64.b64encode(("%s:%s" % (self.user, self.password)).encode()).decode()
        req.add_header("Authorization", "Basic " + creds)
        self.token = _request(req, self.context).strip()

    def _call(self, method, path):
        for attempt in (0, 1):
            if self.token is None:
                self._authenticate()
            req = urllib.request.Request(self.base_url + path, method=method)
            req.add_header("Authorization", "Bearer " + self.token)
            try:
                return _request(req, self.context)
            except ApiError as e:
                if e.status == 401 and attempt == 0:
                    self.token = None
                    continue
                raise

    def get(self, path):
        return json.loads(self._call("GET", path))

    def get_text(self, path):
        return self._call("GET", path)

    def put(self, path):
        return json.loads(self._call("PUT", path))


class Kube:
    """Minimal in-cluster Kubernetes client (read StatefulSets)."""

    def __init__(self, namespace):
        self.namespace = namespace
        self.base_url = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"],
                                           os.environ.get("KUBERNETES_SERVICE_PORT", "443"))
        self.context = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))

    def get_statefulset(self, name):
        with open(os.path.join(SA_DIR, "token")) as f:
            token = f.read().strip()
        req = urllib.request.Request("%s/apis/apps/v1/namespaces/%s/statefulsets/%s"
                                     % (self.base_url, self.namespace, name))
        req.add_header("Authorization", "Bearer " + token)
        return json.loads(_request(req, self.context))


def rollout_done(sts):
    spec, status, meta = sts.get("spec", {}), sts.get("status", {}), sts.get("metadata", {})
    replicas = spec.get("replicas", 1)
    return (status.get("observedGeneration", 0) >= meta.get("generation", 0)
            and status.get("updatedReplicas", 0) == replicas
            and status.get("readyReplicas", 0) == replicas
            and status.get("currentRevision") == status.get("updateRevision"))


def expected_nodes(env_value):
    return [n for n in env_value.split(",") if n]


def ruleset_digest(api, node):
    """SHA-256 of the decoders and rules analysisd has loaded on `node`, or None."""
    h = hashlib.sha256()
    try:
        for kind in ("decoders", "rules"):
            items = api.get("/cluster/%s/configuration/analysis/%s" % (node, kind))["data"]["affected_items"]
            h.update(json.dumps(items, sort_keys=True, separators=(",", ":")).encode())
    except (ApiError, KeyError, TypeError, ValueError):
        return None
    return h.hexdigest()


def mismatched(digests, master):
    want = digests.get(master)
    return sorted(n for n, d in digests.items() if d is None or d != want)


def reload_failures(response):
    lines = []
    for item in (response.get("data") or {}).get("failed_items", []):
        ids = item.get("id", [])
        nodes = ", ".join(ids) if isinstance(ids, list) else str(ids)
        lines.append("%s: %s" % (nodes, (item.get("error") or {}).get("message", "unknown error")))
    return lines


def _names(items):
    return [i["info"]["name"] for i in items]


def main(api, kube, env, clock, sleep, log):
    timeout = float(env["TIMEOUT_SECONDS"])
    interval = float(env["POLL_INTERVAL_SECONDS"])
    deadline = clock() + timeout
    nodes = expected_nodes(env["EXPECTED_NODES"])
    master = nodes[0]

    def wait(what, check, hint=""):
        """Poll `check() -> (done, pending)` until done or the deadline."""
        pending = None
        while True:
            try:
                done, pending = check()
            except ApiError as e:
                done, pending = False, "API: %s" % e
            if done:
                return True
            if clock() + interval > deadline:
                log("timeout: %s: %s%s" % (what, pending, hint))
                return False
            sleep(interval)

    # 1. Rollout of both manager StatefulSets.
    sets = [s for s in (env["MASTER_STS"], env.get("WORKER_STS", "")) if s]

    def rolled_out():
        left = [s for s in sets if not rollout_done(kube.get_statefulset(s))]
        return not left, ", ".join(left)

    if not wait("StatefulSets not rolled out", rolled_out):
        return 1
    log("rollout complete: %s" % ", ".join(sets))

    # 2. Every expected node connected, and its ruleset files synced with the master.
    def connected():
        names = set(_names(api.get("/cluster/healthcheck")["data"]["affected_items"]))
        missing = [n for n in nodes if n not in names]
        return not missing, ", ".join(missing)

    if not wait("nodes not connected", connected):
        return 1

    def synced():
        items = api.get("/cluster/ruleset/synchronization")["data"]["affected_items"]
        ok = {i["name"] for i in items if i.get("synced")}
        left = [n for n in nodes if n not in ok]
        return not left, ", ".join(left)

    if not wait("ruleset files not synced on", synced):
        return 1
    log("all nodes connected and synced: %s" % ", ".join(nodes))

    # 3. The master serves the ConfigMap's ruleset (it reads it at startup).
    for name, path, env_key in (("local_rules.xml", "/rules/files/local_rules.xml?raw=true", "LOCAL_RULES_FILE"),
                                ("local_decoder.xml", "/decoders/files/local_decoder.xml?raw=true",
                                 "LOCAL_DECODER_FILE")):
        with open(env[env_key]) as f:
            want = f.read().strip()
        if api.get_text(path).strip() != want:
            log("master %s differs from the ConfigMap; was the master restarted (autoreload.enabled)?" % name)
            return 1

    # 4. Already running the master's ruleset everywhere: nothing to do.
    def digests():
        return {n: ruleset_digest(api, n) for n in nodes}

    stale = mismatched(digests(), master)
    if not stale:
        log("ruleset already up to date on all nodes, no reload")
        return 0

    # 5. One reload. Workers apply it at the end of their next integrity cycle.
    log("reloading ruleset on: %s" % ", ".join(stale))
    response = api.put("/cluster/analysisd/reload")
    failures = reload_failures(response)
    if failures:
        for line in failures:
            log(line)
        log("ruleset reload failed; the nodes above keep their previous ruleset")
        return 1
    for item in (response.get("data") or {}).get("affected_items", []):
        msg = str(item.get("msg", ""))
        if msg:
            log("%s: %s" % (item.get("name", "?"), msg[:300]))

    # 6. Wait until every node reports the master's ruleset in memory.
    def converged():
        left = mismatched(digests(), master)
        return not left, ", ".join(left)

    if not wait("nodes not running the master's ruleset", converged, "; check logs/cluster.log on them"):
        return 1
    log("ruleset reloaded on all nodes")

    # 7. Informational: the reload line each node logged.
    for n in nodes:
        try:
            q = urllib.parse.quote("Ruleset reloaded successfully")
            items = api.get("/cluster/%s/logs?tag=wazuh-analysisd&search=%s&limit=1" % (n, q))["data"]["affected_items"]
            log("%s: %s" % (n, items[0]["timestamp"] if items else "no reload line in the last log entries"))
        except (ApiError, KeyError, IndexError, TypeError):
            pass
    return 0


if __name__ == "__main__":
    e = dict(os.environ)
    api = WazuhApi(e["WAZUH_API_URL"], e["API_USERNAME"], e["API_PASSWORD"])
    rc = main(api, Kube(e["NAMESPACE"]), e, time.monotonic, time.sleep, lambda s: print(s, flush=True))
    sys.exit(rc)
