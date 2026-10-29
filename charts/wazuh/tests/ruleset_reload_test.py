#!/usr/bin/env python3
"""Unit tests for files/ruleset-reload.py (stdlib only, no cluster needed).

Usage: python3 charts/wazuh/tests/ruleset_reload_test.py
"""
import importlib.util
import os
import sys
import unittest

# Importing files/ruleset-reload.py must not leave a __pycache__ in the chart's files/.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "ruleset_reload", os.path.join(HERE, "..", "files", "ruleset-reload.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

MASTER = "t-wazuh-manager-master-0"
W0, W1, W2 = ("t-wazuh-manager-worker-%d" % i for i in range(3))
NODES = [MASTER, W0, W1, W2]
RULES_XML = "<group name=\"t,\"><rule id=\"100001\" level=\"3\"/></group>"
DECODER_XML = "<decoder name=\"t\"><prematch>^T v2 </prematch></decoder>"
OLD_LINE, NEW_LINE = "2026-10-28T00:00:00Z", "2026-10-29T10:00:00Z"


def sts(name, revision="r2", current="r2", replicas=3, ready=3, updated=3, generation=2, observed=2):
    return {"metadata": {"name": name, "generation": generation},
            "spec": {"replicas": replicas},
            "status": {"observedGeneration": observed, "replicas": replicas, "readyReplicas": ready,
                       "updatedReplicas": updated, "currentRevision": current, "updateRevision": revision}}


def ruleset(version):
    return {"decoders": {"data": {"affected_items": [{"decoders": [{"name": "t", "prematch": "^T %s " % version}]}],
                                  "failed_items": []}},
            "rules": {"data": {"affected_items": [{"rules": [{"sigid": 100001, "comment": "t %s" % version}]}],
                               "failed_items": []}}}


def failed_read(node):
    return {"error": 1, "data": {"affected_items": [], "failed_items": [
        {"id": [node], "error": {"message": "Error reading the configuration"}}]}}


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def clock(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakeKube:
    def __init__(self, sets=None):
        self.sets = sets or {}
        self.timeouts = []

    def get_statefulset(self, name, timeout):
        self.timeouts.append(timeout)
        v = self.sets.get(name) or sts(name)
        return v(self) if callable(v) else v


class FakeApi:
    """Answers per node from `versions` (node -> callable(api) -> "v1"/"v2", "failed" for a
    failed_items answer, or an exception to raise). `reloaded` (node -> callable(api) -> bool or
    an exception) says whether the node has logged a reload line newer than the baseline; by
    default every node logs one once the reload was requested."""

    def __init__(self, versions, connected=None, synced=None, files=None, reload_response=None, reloaded=None):
        self.versions = versions
        self.connected = connected if connected is not None else (lambda api: NODES)
        self.synced = synced if synced is not None else (lambda api: NODES)
        self.files = files or {"/rules/files/local_rules.xml?raw=true": RULES_XML,
                               "/decoders/files/local_decoder.xml?raw=true": DECODER_XML}
        self.reload_response = reload_response or {
            "error": 0, "data": {"affected_items": [{"name": n, "msg": "ok"} for n in NODES], "failed_items": []}}
        self.reloaded = reloaded or {}
        self.calls = []
        self.timeouts = []
        self.reloads = 0

    def _value(self, fn):
        v = fn(self)
        if isinstance(v, Exception):
            raise v
        return v

    def get(self, path, timeout):
        self.calls.append(("GET", path))
        self.timeouts.append(timeout)
        if path == "/cluster/healthcheck":
            return {"data": {"affected_items": [{"info": {"name": n}} for n in self.connected(self)]}}
        if path == "/cluster/ruleset/synchronization":
            ok = self.synced(self)
            return {"data": {"affected_items": [{"name": n, "synced": n in ok} for n in self.connected(self)]}}
        for kind in ("decoders", "rules"):
            suffix = "/configuration/analysis/" + kind
            if path.endswith(suffix):
                node = path[len("/cluster/"):-len(suffix)]
                v = self._value(self.versions[node])
                return failed_read(node) if v == "failed" else ruleset(v)[kind]
        if "/logs?" in path:
            node = path[len("/cluster/"):path.index("/logs?")]
            new = self._value(self.reloaded.get(node, lambda a: a.reloads > 0))
            return {"data": {"affected_items": [{"timestamp": NEW_LINE if new else OLD_LINE,
                                                 "description": " Ruleset reloaded successfully"}],
                             "failed_items": []}}
        raise AssertionError("unexpected GET " + path)

    def get_text(self, path, timeout):
        self.calls.append(("GET", path))
        self.timeouts.append(timeout)
        return self.files[path]

    def put(self, path, timeout):
        self.calls.append(("PUT", path))
        self.timeouts.append(timeout)
        assert path == "/cluster/analysisd/reload", path
        self.reloads += 1
        return self.reload_response


def after_reload(before, after):
    return lambda api: after if api.reloads else before


class Rules(unittest.TestCase):
    def setUp(self):
        self.files = {}
        for name, content in (("rules", RULES_XML), ("decoder", DECODER_XML)):
            path = os.path.join(self.tmp(), "local_%s.xml" % name)
            with open(path, "w") as f:
                f.write(content + "\n")
            self.files[name] = path
        self.env = {"MASTER_STS": "t-wazuh-manager-master", "WORKER_STS": "t-wazuh-manager-worker",
                    "EXPECTED_NODES": ",".join(NODES), "TIMEOUT_SECONDS": "240", "POLL_INTERVAL_SECONDS": "10",
                    "LOCAL_RULES_FILE": self.files["rules"], "LOCAL_DECODER_FILE": self.files["decoder"]}
        self.logs = []
        self.time = FakeClock()

    def tmp(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        return d

    def run_main(self, api, kube=None, **env):
        e = dict(self.env, **env)
        return m.main(api, kube or FakeKube(), e, self.time.clock, self.time.sleep, self.logs.append)

    def log(self):
        return "\n".join(self.logs)

    def ruleset_calls(self, api, node):
        return sum(1 for c in api.calls if c[1].startswith("/cluster/%s/configuration/" % node))

    def slow(self, api, seconds):
        """Make every GET take `seconds`, cut short (and failing) by the request timeout."""
        orig = api.get

        def get(path, timeout):
            if timeout < seconds:
                self.time.t += timeout
                raise m.ApiError(0, "timed out")
            self.time.t += seconds
            return orig(path, timeout)

        api.get = get

    # --- pure helpers ---

    def test_rollout_done(self):
        self.assertTrue(m.rollout_done(sts("x")))

    def test_rollout_done_requires_same_revision(self):
        self.assertFalse(m.rollout_done(sts("x", current="r1")))

    def test_rollout_done_requires_all_ready(self):
        self.assertFalse(m.rollout_done(sts("x", ready=2)))

    def test_rollout_done_requires_observed_generation(self):
        self.assertFalse(m.rollout_done(sts("x", observed=1)))

    def test_expected_nodes(self):
        self.assertEqual(m.expected_nodes(",".join(NODES)), NODES)

    def test_expected_nodes_without_workers(self):
        self.assertEqual(m.expected_nodes(MASTER), [MASTER])

    def test_reload_failures_formats_failed_items(self):
        resp = {"data": {"failed_items": [{"id": ["w1"], "error": {"message": "Failed to reload ruleset"}}]}}
        self.assertEqual(m.reload_failures(resp), ["w1: Failed to reload ruleset"])

    def test_ruleset_digest_none_on_api_error(self):
        api = FakeApi({MASTER: lambda a: m.ApiError(400, "node not connected")})
        self.assertIsNone(m.ruleset_digest(api, MASTER, 30))

    def test_ruleset_digest_none_on_failed_items(self):
        api = FakeApi({MASTER: lambda a: "failed"})
        self.assertIsNone(m.ruleset_digest(api, MASTER, 30))

    def test_ruleset_digest_none_on_empty_result(self):
        api = FakeApi({MASTER: lambda a: "v2"})
        orig = api.get
        api.get = lambda path, timeout: {"data": {"affected_items": [], "failed_items": []}} \
            if "rules" in path else orig(path, timeout)
        self.assertIsNone(m.ruleset_digest(api, MASTER, 30))

    def test_ruleset_digest_differs_between_versions(self):
        api = FakeApi({W0: lambda a: "v1", W1: lambda a: "v2", W2: lambda a: "v2"})
        self.assertNotEqual(m.ruleset_digest(api, W0, 30), m.ruleset_digest(api, W1, 30))
        self.assertEqual(m.ruleset_digest(api, W1, 30), m.ruleset_digest(api, W2, 30))

    # --- main flow ---

    def test_reloads_once_even_when_digests_match(self):
        # The digest does not cover every rule option (no_full_log, json_null_field...): never skip.
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        self.assertEqual(self.run_main(api), 0)
        self.assertEqual(api.reloads, 1)
        self.assertIn("reloading the ruleset on all nodes", self.log())
        self.assertIn("ruleset reloaded on all nodes", self.log())

    def test_stale_worker_converges(self):
        api = FakeApi({MASTER: lambda a: "v2", W0: lambda a: "v2",
                       W1: after_reload("v1", "v2"), W2: lambda a: "v2"})
        self.assertEqual(self.run_main(api), 0)
        self.assertEqual(api.reloads, 1)

    def test_no_ruleset_read_before_the_reload(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        self.run_main(api)
        first_put = api.calls.index(("PUT", "/cluster/analysisd/reload"))
        self.assertFalse([c for c in api.calls[:first_put] if "/configuration/" in c[1]])

    def test_timeout_names_nodes_still_on_another_ruleset(self):
        api = FakeApi({MASTER: lambda a: "v2", W0: after_reload("v1", "v2"),
                       W1: lambda a: "v2", W2: lambda a: "v1"})
        self.assertEqual(self.run_main(api), 1)
        self.assertEqual(api.reloads, 1)
        self.assertIn("timeout: nodes that did not reload the master's ruleset: %s; check logs/cluster.log "
                      "and logs/ossec.log on them" % W2, self.log())

    def test_node_without_a_new_reload_line_times_out(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES}, reloaded={W1: lambda a: False})
        self.assertEqual(self.run_main(api), 1)
        self.assertIn("timeout: nodes that did not reload the master's ruleset: %s;" % W1, self.log())

    def test_poll_treats_node_errors_as_not_done(self):
        calls = {"n": 0}

        def w0(api):
            if not api.reloads:
                return "v1"
            calls["n"] += 1
            return m.ApiError(400, "not connected") if calls["n"] <= 2 else "v2"

        api = FakeApi({MASTER: lambda a: "v2", W0: w0, W1: lambda a: "v2", W2: lambda a: "v2"})
        self.assertEqual(self.run_main(api), 0)
        self.assertEqual(api.reloads, 1)

    def test_node_erroring_after_reload_is_named_at_timeout(self):
        api = FakeApi({MASTER: lambda a: "v2", W0: after_reload("v1", m.ApiError(400, "not connected")),
                       W1: lambda a: "v2", W2: lambda a: "v2"})
        self.assertEqual(self.run_main(api), 1)
        self.assertIn("timeout: nodes that did not reload the master's ruleset: %s;" % W0, self.log())

    def test_failed_items_reads_never_count_as_reloaded(self):
        api = FakeApi({MASTER: lambda a: "v2", W0: after_reload("v1", "failed"),
                       W1: lambda a: "v2", W2: lambda a: "v2"})
        self.assertEqual(self.run_main(api), 1)
        self.assertIn("timeout: nodes that did not reload the master's ruleset: %s;" % W0, self.log())

    def test_all_reads_failing_never_succeeds(self):
        api = FakeApi({n: (lambda a: "failed") for n in NODES})
        self.assertEqual(self.run_main(api), 1)
        self.assertNotIn("ruleset reloaded on all nodes", self.log())

    def test_master_ruleset_read_once(self):
        polls = {"n": 0}

        def w1(api):
            if not api.reloads:
                return "v1"
            polls["n"] += 1
            return "v2" if polls["n"] > 3 else "v1"

        api = FakeApi({MASTER: lambda a: "v2", W0: lambda a: "v2", W1: w1, W2: lambda a: "v2"})
        self.assertEqual(self.run_main(api), 0)
        self.assertEqual(self.ruleset_calls(api, MASTER), 2)

    def test_reloaded_nodes_not_polled_again(self):
        polls = {"n": 0}

        def w1(api):
            if not api.reloads:
                return "v1"
            polls["n"] += 1
            return "v2" if polls["n"] > 3 else "v1"

        api = FakeApi({MASTER: lambda a: "v2", W0: after_reload("v1", "v2"), W1: w1, W2: lambda a: "v2"})
        self.assertEqual(self.run_main(api), 0)
        self.assertEqual(self.ruleset_calls(api, W0), 2)  # first poll, decoders and rules
        self.assertGreater(self.ruleset_calls(api, W1), 2)

    def test_master_ruleset_unreadable_times_out(self):
        api = FakeApi({n: (lambda a: m.ApiError(500, "boom")) for n in NODES})
        self.assertEqual(self.run_main(api), 1)
        self.assertIn("timeout: master ruleset not readable: " + MASTER, self.log())

    def test_unreadable_baseline_times_out_without_reload(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES},
                      reloaded={W0: lambda a: m.ApiError(502, "proxy error")})
        self.assertEqual(self.run_main(api), 1)
        self.assertEqual(api.reloads, 0)
        self.assertIn("timeout: reload log not readable on: " + W0, self.log())

    def test_master_file_differs_fails_before_reload(self):
        api = FakeApi({n: (lambda a: "v1") for n in NODES},
                      files={"/rules/files/local_rules.xml?raw=true": "<group/>",
                             "/decoders/files/local_decoder.xml?raw=true": DECODER_XML})
        self.assertEqual(self.run_main(api), 1)
        self.assertEqual(api.reloads, 0)
        self.assertIn("master local_rules.xml differs from the ConfigMap", self.log())

    def test_waits_for_missing_node_then_times_out(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES}, connected=lambda a: [MASTER, W0, W2])
        self.assertEqual(self.run_main(api), 1)
        self.assertEqual(api.reloads, 0)
        self.assertIn("timeout: nodes not connected: " + W1, self.log())

    def test_waits_for_unsynced_node_then_times_out(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES}, synced=lambda a: [MASTER, W0, W1])
        self.assertEqual(self.run_main(api), 1)
        self.assertEqual(api.reloads, 0)
        self.assertIn("timeout: ruleset files not synced on: " + W2, self.log())

    def test_reload_failed_item_fails(self):
        resp = {"error": 1, "data": {"affected_items": [],
                                     "failed_items": [{"id": [MASTER], "error": {"message": "Failed to reload ruleset"}}]}}
        api = FakeApi({MASTER: lambda a: "v2", W0: lambda a: "v1", W1: lambda a: "v1", W2: lambda a: "v1"},
                      reload_response=resp)
        self.assertEqual(self.run_main(api), 1)
        self.assertEqual(api.reloads, 1)
        self.assertIn("%s: Failed to reload ruleset" % MASTER, self.log())

    def test_waits_for_rollout_then_times_out(self):
        kube = FakeKube({"t-wazuh-manager-worker": sts("t-wazuh-manager-worker", current="r1")})
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        self.assertEqual(self.run_main(api, kube), 1)
        self.assertIn("timeout: StatefulSets not rolled out: t-wazuh-manager-worker", self.log())
        self.assertFalse(api.calls)

    def test_without_workers_only_the_master_is_reloaded(self):
        api = FakeApi({MASTER: lambda a: "v2"}, connected=lambda a: [MASTER], synced=lambda a: [MASTER])
        self.assertEqual(self.run_main(api, WORKER_STS="", EXPECTED_NODES=MASTER), 0)
        self.assertEqual(api.reloads, 1)

    def test_api_unavailable_is_waited_for(self):
        state = {"n": 0}
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        orig = api.get

        def flaky(path, timeout):
            if path == "/cluster/healthcheck" and state["n"] < 3:
                state["n"] += 1
                raise m.ApiError(0, "connection refused")
            return orig(path, timeout)

        api.get = flaky
        self.assertEqual(self.run_main(api), 0)

    def test_unexpected_response_is_waited_for(self):
        state = {"n": 0}
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        orig = api.get

        def odd(path, timeout):
            if path == "/cluster/healthcheck" and state["n"] < 2:
                state["n"] += 1
                return {"error": 1}
            return orig(path, timeout)

        api.get = odd
        self.assertEqual(self.run_main(api), 0)

    def test_reload_api_error_is_reported(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES})

        def put(path, timeout):
            raise m.ApiError(0, "connection refused")

        api.put = put
        self.assertEqual(self.run_main(api), 1)
        self.assertIn("master API error while reloading the ruleset: HTTP 0: connection refused", self.log())

    def test_file_check_api_error_is_reported(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES})

        def get_text(path, timeout):
            raise m.ApiError(503, "unavailable")

        api.get_text = get_text
        self.assertEqual(self.run_main(api), 1)
        self.assertIn("master API error while reading local_rules.xml: HTTP 503: unavailable", self.log())

    # --- time budget ---

    def test_slow_checks_do_not_overrun_the_deadline(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES}, connected=lambda a: [MASTER, W0, W1])
        self.slow(api, 50)
        self.assertEqual(self.run_main(api), 1)
        self.assertIn("timeout: nodes not connected:", self.log())
        self.assertLessEqual(self.time.t, 240)

    def test_slow_successful_checks_stop_at_the_budget(self):
        # Every answer succeeds but takes 29s: the run must end in time, not report success late.
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        self.slow(api, 29)
        rc = self.run_main(api)
        self.assertLessEqual(self.time.t, 240)
        if rc == 0:
            self.assertIn("ruleset reloaded on all nodes", self.log())
        else:
            self.assertIn("timeout:", self.log())

    def test_requests_get_at_most_the_remaining_budget(self):
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        kube = FakeKube()
        self.time.t = 0
        self.assertEqual(self.run_main(api, kube, TIMEOUT_SECONDS="45"), 0)
        self.assertTrue(all(0 < t <= 30 for t in api.timeouts + kube.timeouts), api.timeouts + kube.timeouts)

    def test_budget_exhausted_stops_before_any_request(self):
        kube = FakeKube({"t-wazuh-manager-worker": sts("t-wazuh-manager-worker", current="r1")})
        api = FakeApi({n: (lambda a: "v2") for n in NODES})
        self.assertEqual(self.run_main(api, kube, TIMEOUT_SECONDS="30"), 1)
        self.assertLessEqual(self.time.t, 30)


if __name__ == "__main__":
    unittest.main(verbosity=1)
