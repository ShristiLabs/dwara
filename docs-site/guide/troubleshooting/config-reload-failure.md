# Config reload failure

A config reload failure means the gateway could not apply a new
configuration. The running configuration is untouched; the gateway
continues serving with the previous config.

## Symptoms

- The admin API returns a validation error on `PATCH /config`.
- The file watcher logs a reload failure with the validation issues.
- The gateway continues running with the previous config.

## Likely causes

### Validation errors

The new config has schema violations, missing references, or
invalid values.

**Diagnose:**

```sh
# Validate the config without applying it
dwara validate --config path/to/new-config.yaml

# Check the admin API for the last reload error
curl -k https://127.0.0.1:2019/config | jq '.last_reload_error'
```

The validation output lists every issue with the entity name and
field path. Common issues:

- A route references a service that does not exist.
- A consumer references a policy that does not exist.
- An upstream has no endpoints.
- A secret reference `${VAR}` does not resolve (the environment
  variable is not set).

**Fix:** Correct the validation issues in the config file and
retry. The validation output tells you exactly what to fix.

### Secret reference not found

A `${VAR}` secret reference in the config does not resolve because
the environment variable is not set in the gateway's environment.

**Diagnose:**

```sh
# Check if the environment variable is set
echo $MY_SECRET_VAR

# Validate the config (it will report unresolvable references)
dwara validate --config path/to/new-config.yaml
```

**Fix:** Set the environment variable in the gateway's environment
and restart, or use a file-based secret reference:

```yaml
# Environment variable
auth:
  value: ${MY_API_KEY}

# File-based
auth:
  value: ${file:/etc/dwara/secrets/api-key}
```

### YAML syntax error

The config file has invalid YAML syntax.

**Diagnose:**

```sh
# Validate the config
dwara validate --config path/to/new-config.yaml
```

**Fix:** Fix the YAML syntax. Common issues include incorrect
indentation, missing quotes around strings with special characters,
and tabs instead of spaces.

### Config file not found

The file watcher is watching a path that does not exist or has been
moved.

**Diagnose:**

```sh
# Check if the config file exists
ls -la /path/to/dwara.yaml

# Check the gateway's startup log for the config path
journalctl -u dwara | grep "config file"
```

**Fix:** Ensure the config file exists at the path the gateway was
started with. Set `DWARA_CONFIG` to the correct path.

## See also

- [CLI](../cli)
- [Operations](../operations)
