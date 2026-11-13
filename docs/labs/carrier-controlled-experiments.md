# Optional disposable carrier lab plans

These three representative plans are **unexecuted**. They are optional experiments, separate from
the offline corpus and the short MobileWork user-validation report. No injection command is part
of the evaluator or runs automatically.

Use a disposable Linux VM/container with no customer data. Record OS/kernel, tool versions and
the exact local operation before starting. Enter a new network namespace with explicit lab opt-in:

```sh
NETOPS_LAB_OPT_IN=1 NETOPS_PARENT_NETNS="$(readlink /proc/self/ns/net)" unshare --user --map-root-user --net sh
```

Inside that shell, verify both conditions before any command below:

```sh
test "$NETOPS_LAB_OPT_IN" = 1 || exit 1
test "$(readlink /proc/self/ns/net)" != "$NETOPS_PARENT_NETNS" || exit 1
ip link set lo up
```

Only namespace loopback addresses are used. If namespaces, permissions or required tools are
unavailable, record setup unavailable and stop. Do not move these commands onto host interfaces.
All services and files below are disposable lab resources; stop their recorded PIDs before exit.

## Three representative inputs and outputs

| Plan | Baseline and input | Injection and proof | Cleanup and original-operation recovery |
| --- | --- | --- | --- |
| Local HTTP delay | Start `python3 -m http.server 18080 --bind 127.0.0.1` in a fresh empty lab directory. Save the response and elapsed time from `curl --max-time 5 -sS -o /dev/null -w '%{http_code} %{time_total}\n' http://127.0.0.1:18080/`. | `tc qdisc add dev lo root netem delay 100ms`; save `tc -s qdisc show dev lo` and repeat that same curl command. Expected: increased measured time; record the actual value rather than asserting a fixed end-to-end delay. | `tc qdisc del dev lo root`; repeat the same URL/request, compare with the baseline and save the final qdisc listing. Stop the HTTP server. |
| Local TCP proxy delay | With the same HTTP server, start `toxiproxy-server -host 127.0.0.1 -port 8474`. POST the proxy definition below; use the same curl operation through port 18081 and save its baseline. | POST the latency toxic below. Save the API response/listing and repeat the same port-18081 request. Expected: added downstream latency; proxy configuration alone is not proof it took effect. | DELETE `/proxies/lab-http/toxics/lab-delay`; repeat the exact proxied request, then DELETE `/proxies/lab-http`. Save the empty proxy listing and stop both servers. |
| Local DNS answer change | Run CoreDNS with the baseline Corefile below. Save `dig @127.0.0.1 -p 1053 service.lab.test A +tries=1 +time=2`. Expected baseline: loopback A answer. | Replace only the template body with `rcode NXDOMAIN`, restart that recorded local server, and repeat the same dig command. Save the actual status and query output. | Restore the baseline Corefile, restart the same local service, and repeat the original query. Save its restored answer; stop CoreDNS and check that the local listener is gone. |

Toxiproxy requests use `curl --fail-with-body -sS -H 'Content-Type: application/json'` and only
`http://127.0.0.1:8474`. POST `/proxies` with:

```json
{"name":"lab-http","listen":"127.0.0.1:18081","upstream":"127.0.0.1:18080","enabled":true}
```

POST `/proxies/lab-http/toxics` with:

```json
{"name":"lab-delay","type":"latency","stream":"downstream","toxicity":1.0,"attributes":{"latency":200,"jitter":0}}
```

The baseline Corefile, started with `coredns -conf Corefile`, is:

```text
lab.test:1053 {
    bind 127.0.0.1
    template IN A lab.test {
        answer "{{ .Name }} 60 IN A 127.0.0.1"
    }
}
```

The command forms follow [netem's manual](https://man7.org/linux/man-pages/man8/tc-netem.8.html),
[Toxiproxy's API](https://github.com/Shopify/toxiproxy/blob/main/README.md) and
[CoreDNS template syntax](https://coredns.io/plugins/template/). Installed versions and actual
behavior must be recorded when a person runs the plan; these are not current passing results.

## Evidence required for a valid experiment

Keep one operation identity through baseline, injection and recovery: URL/proxy path or
resolver/name/type, request parameters, vantage and sampling conditions. Save six small evidence
records: baseline, injection proof, diagnosis, cleanup, original-operation recovery and residual
resource check. Include file hashes and actual timestamps. The diagnosis input is only the permitted
observations; withhold the injection plan and expected answer from the evaluated adapter.

After cleanup, check `tc -s qdisc show dev lo`, the local proxy inventory, `ss -lntup` and the recorded
lab processes as applicable; save the results and exit the namespace. A failed/missing injection,
cleanup or recovery is an invalid experiment, not a model success or failure. Do not substitute
another healthy URL/query for the original operation. Unexecuted plans remain unexecuted.
