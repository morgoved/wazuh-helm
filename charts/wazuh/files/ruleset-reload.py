"""Make every Wazuh node run the master's ruleset after a deployment.

Workers start analysisd before the cluster integrity sync delivers new rules and
decoders, and nothing reloads it afterwards, so they keep the previous ruleset.
This Job waits for the manager rollout and the sync, reloads the ruleset once, and
waits until every node has logged a new successful reload and runs the master's
decoders and rules in memory.

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
REQUEST_TIMEOUT = 30
RELOAD_LINE = "Ruleset reloaded successfully"


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__("HTTP %s: %s" % (status, body[:500]))
        self.status = status
        self.body = body


class BudgetExhausted(ApiError):
    def __init__(self, budget):
        super().__init__(0, "time budget of %ss exhausted" % budget)


def _request(req, context, timeout):
    try:
        with urllib.request.urlopen(req, context=context, timeout=timeout) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as e:
        raise ApiError(e.code, e.read().decode(errors="replace"))
    except (urllib.error.URLError, OSError) as e:
        raise ApiError(0, str(e))


class WazuhApi:
    """Wazuh API client. The chart's API certificate is self-signed: not verified.

    `timeout` is a callable returning the timeout of the next HTTP request; it is called
    before each one (authentication and the retry after a 401 included)."""

    def __init__(self, base_url, user, password):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.token = None
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def _authenticate(self, timeout):
        req = urllib.request.Request(self.base_url + "/security/user/authenticate?raw=true", method="POST")
        creds = base64.b64encode(("%s:%s" % (self.user, self.password)).encode()).decode()
        req.add_header("Authorization", "Basic " + creds)
        self.token = _request(req, self.context, timeout()).strip()

    def _call(self, method, path, timeout):
        for attempt in (0, 1):
            if self.token is None:
                self._authenticate(timeout)
            req = urllib.request.Request(self.base_url + path, method=method)
            req.add_header("Authorization", "Bearer " + self.token)
            try:
                return _request(req, self.context, timeout())
            except ApiError as e:
                if e.status == 401 and attempt == 0:
                    self.token = None
                    continue
                raise

    def get(self, path, timeout):
        return json.loads(self._call("GET", path, timeout))

    def get_text(self, path, timeout):
        return self._call("GET", path, timeout)

    def put(self, path, timeout):
        return json.loads(self._call("PUT", path, timeout))


class Kube:
    """Minimal in-cluster Kubernetes client (read StatefulSets). `timeout` as in WazuhApi."""

    def __init__(self, namespace):
        self.namespace = namespace
        self.base_url = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"],
                                           os.environ.get("KUBERNETES_SERVICE_PORT", "443"))
        self.context = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))

    def get_statefulset(self, name, timeout):
        with open(os.path.join(SA_DIR, "token")) as f:
            token = f.read().strip()
        req = urllib.request.Request("%s/apis/apps/v1/namespaces/%s/statefulsets/%s"
                                     % (self.base_url, self.namespace, name))
        req.add_header("Authorization", "Bearer " + token)
        return json.loads(_request(req, self.context, timeout()))


def rollout_done(sts):
    spec, status, meta = sts.get("spec", {}), sts.get("status", {}), sts.get("metadata", {})
    replicas = spec.get("replicas", 1)
    return (status.get("observedGeneration", 0) >= meta.get("generation", 0)
            and status.get("updatedReplicas", 0) == replicas
            and status.get("readyReplicas", 0) == replicas
            and status.get("currentRevision") == status.get("updateRevision"))


def expected_nodes(env_value):
    return [n for n in env_value.split(",") if n]


def reload_failures(response):
    lines = []
    for item in (response.get("data") or {}).get("failed_items", []):
        ids = item.get("id", [])
        nodes = ", ".join(ids) if isinstance(ids, list) else str(ids)
        lines.append("%s: %s" % (nodes, (item.get("error") or {}).get("message", "unknown error")))
    return lines


def affected(response, allow_empty=False):
    """affected_items of a Wazuh API answer. The API answers HTTP 200 with failed_items
    when a node cannot answer: that, or an empty result, is an error."""
    failures = reload_failures(response)
    if failures:
        raise ApiError(200, "failed_items: " + "; ".join(failures))
    items = response["data"]["affected_items"]
    if not items and not allow_empty:
        raise ApiError(200, "empty affected_items")
    return items


def ruleset_digest(api, node, timeout):
    """SHA-256 of the decoders and rules analysisd has loaded on `node`, or None."""
    h = hashlib.sha256()
    try:
        for kind in ("decoders", "rules"):
            items = affected(api.get("/cluster/%s/configuration/analysis/%s" % (node, kind), timeout))
            if not all(i.get(kind) for i in items):
                return None
            h.update(json.dumps(items, sort_keys=True, separators=(",", ":")).encode())
    except (ApiError, KeyError, TypeError, ValueError, AttributeError):
        return None
    return h.hexdigest()


def last_reload_line(api, node, timeout):
    """Timestamp of the newest "Ruleset reloaded successfully" analysisd line on `node`, or ""."""
    path = "/cluster/%s/logs?tag=wazuh-analysisd&search=%s&sort=-timestamp&limit=1" % (
        node, urllib.parse.quote(RELOAD_LINE))
    items = affected(api.get(path, timeout), allow_empty=True)
    return items[0]["timestamp"] if items else ""


def _names(items):
    return [i["info"]["name"] for i in items]


def main(api, kube, env, clock, sleep, log):
    budget = float(env["TIMEOUT_SECONDS"])
    interval = float(env["POLL_INTERVAL_SECONDS"])
    deadline = clock() + budget
    nodes = expected_nodes(env["EXPECTED_NODES"])
    master = nodes[0]

    def remaining():
        """Timeout for the next request: never past the deadline. Passed down uncalled, so
        that each HTTP request recomputes it."""
        left = deadline - clock()
        if left < 1:
            raise BudgetExhausted(env["TIMEOUT_SECONDS"])
        return min(REQUEST_TIMEOUT, left)

    def wait(what, check, hint=""):
        """Poll `check() -> (done, pending)` until done, or until the next poll could end
        past the deadline (counting how long the last one took)."""
        pending = None
        while True:
            started = clock()
            try:
                done, pending = check()
            except BudgetExhausted as e:
                # Report what was still pending, not the budget running out mid-check.
                done, pending = False, pending or "API: %s" % e
            except ApiError as e:
                done, pending = False, "API: %s" % e
            except (KeyError, TypeError, ValueError, AttributeError) as e:
                done, pending = False, "unexpected API response: %r" % e
            if done and clock() <= deadline:
                return True
            if done:
                log("timeout: %s: checks finished after the %ss budget" % (what, env["TIMEOUT_SECONDS"]))
                return False
            if clock() + interval + (clock() - started) > deadline:
                log("timeout: %s: %s%s" % (what, pending, hint))
                return False
            sleep(interval)

    # 1. Rollout of both manager StatefulSets.
    sets = [s for s in (env["MASTER_STS"], env.get("WORKER_STS", "")) if s]

    def rolled_out():
        left = [s for s in sets if not rollout_done(kube.get_statefulset(s, remaining))]
        return not left, ", ".join(left)

    if not wait("StatefulSets not rolled out", rolled_out):
        return 1
    log("rollout complete: %s" % ", ".join(sets))

    # 2. Every expected node connected, and its ruleset files synced with the master.
    def connected():
        names = set(_names(affected(api.get("/cluster/healthcheck", remaining))))
        missing = [n for n in nodes if n not in names]
        return not missing, ", ".join(missing)

    if not wait("nodes not connected", connected):
        return 1

    def synced():
        items = affected(api.get("/cluster/ruleset/synchronization", remaining))
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
        try:
            served = api.get_text(path, remaining).strip()
        except ApiError as e:
            log("master API error while reading %s: %s" % (name, e))
            return 1
        if served != want:
            log("master %s differs from the ConfigMap; was the master restarted (autoreload.enabled)?" % name)
            return 1

    # 4. The newest reload line of each node, so that step 6 only counts a reload logged
    # after this request (compared on each node's own clock).
    before = {}

    def read_baseline():
        for n in nodes:
            if n not in before:
                try:
                    before[n] = last_reload_line(api, n, remaining)
                except (ApiError, KeyError, IndexError, TypeError, ValueError):
                    pass
        left = [n for n in nodes if n not in before]
        return not left, ", ".join(left)

    if not wait("reload log not readable on", read_baseline):
        return 1

    # 5. One reload, every run: the loaded ruleset the API shows does not include every
    # rule option, so matching digests do not prove a node is current. Workers apply it
    # at the end of their next integrity cycle.
    log("reloading the ruleset on all nodes")
    try:
        response = api.put("/cluster/analysisd/reload", remaining)
    except ApiError as e:
        log("master API error while reloading the ruleset: %s" % e)
        return 1
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

    # 6. Wait until every node has logged a new successful reload and runs the master's
    # decoders and rules in memory. Each digest pulls a node's whole ruleset through the
    # master API: the master's is read once, and nodes already done are not read again.
    want = {}

    def read_master():
        want["digest"] = ruleset_digest(api, master, remaining)
        return want["digest"] is not None, master

    if not wait("master ruleset not readable", read_master):
        return 1

    pending = list(nodes)

    def reloaded(n):
        try:
            if not last_reload_line(api, n, remaining) > before[n]:
                return False
        except (ApiError, KeyError, IndexError, TypeError, ValueError):
            return False
        return n == master or ruleset_digest(api, n, remaining) == want["digest"]

    def converged():
        pending[:] = [n for n in pending if not reloaded(n)]
        return not pending, ", ".join(pending)

    if not wait("nodes that did not reload the master's ruleset", converged,
                "; check logs/cluster.log and logs/ossec.log on them"):
        return 1
    log("ruleset reloaded on all nodes")
    return 0


if __name__ == "__main__":
    e = dict(os.environ)
    api = WazuhApi(e["WAZUH_API_URL"], e["API_USERNAME"], e["API_PASSWORD"])
    rc = main(api, Kube(e["NAMESPACE"]), e, time.monotonic, time.sleep, lambda s: print(s, flush=True))
    sys.exit(rc)
