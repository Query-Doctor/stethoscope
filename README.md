# Stethoscope

Experimental eBPF-based, database-agnostic query collector. Automatically grabs queries made by your applications without making changes to them.

### Postgres Support
Only postgres is supported right now based on our specific needs.
- Query string
- Response timing
- Connection details (ip:port)
- Process name
- Whether the query is encrypted

Does _not_ currently support getting concrete parameter values for prepared statements. Though it's certainly doable.

```sh
# Listens for postgres queries
docker run privileged -v /sys/kernel/tracing:/sys/kernel/tracing -v /usr/lib:/usr/lib query-doctor/stethoscope
```

```json
{"db":"postgres","ip":"72.144.105.10","port":5432,"pid":3896124,"process_name":"python3","query":"SELECT 999 + 1;","delta":6.289313,"encrypted":true}
{"db":"postgres","ip":"72.144.105.10","port":5432,"pid":3896124,"process_name":"python3","query":"SELECT 999 + 1;","delta":6.252741,"encrypted":true}
{"db":"postgres","ip":"72.144.105.10","port":5432,"pid":3896124,"process_name":"python3","query":"SELECT 999 + 1;","delta":6.238099,"encrypted":true}
{"db":"postgres","ip":"127.0.0.1","port":5432,"pid":3896818,"process_name":"psql","query":"begin; PREPARE q(int) AS SELECT  + 1;","delta":0.570156,"encrypted":false}
{"db":"postgres","ip":"127.0.0.1","port":5432,"pid":3896818,"process_name":"psql","query":"EXECUTE q(42); commit;","delta":0.418718,"encrypted":false}
{"db":"postgres","ip":"127.0.0.1","port":5432,"pid":3897122,"process_name":"psql","query":"select 'hi mom'","delta":0.288139,"encrypted":false}
```

## Contributing

Generate the vmlinux.h file based on your kernel

`TODO: add required dependencies`

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
```

```
go generate && go run .
```
