#!/usr/bin/env python3
"""Renders the Helm chart and checks the manifests reflect the values.

With --schema (the EKS add-on configuration schema), values are generated for every schema
property, and for each property this checks that:
  - `helm template` succeeds,
  - label and annotation keys and values come out as strings, unchanged,
  - the DaemonSet selector stays fixed, since it can't change on an existing add-on,
  - at least one sample value changes the output, unless the property is marked deprecated.
With --values, the same manifest checks run on each given values file.

Usage: test_chart.py --chart <chart dir> (--schema <configuration.schema.json> | --values <file>...)
"""

import argparse
import copy
import json
import subprocess
import sys

import yaml

# Values EKS sets on every install (defaultConfiguration in config.yaml).
EKS_VALUES = {
    "image": {"containerRegistry": "123456789012.dkr.ecr.us-west-2.amazonaws.com"},
    "env": {"EKS_CLUSTER_NAME": "test-cluster"},
}
NAMESPACE = "amazon-network-flow-monitor"

# Keys YAML 1.1 reads as booleans, numbers or null if the chart doesn't quote them.
TRICKY_KEYS = ["example.com/key", "yes", "on", "1", "null"]

# Samples for properties the schema leaves free-form.
SAMPLES = {
    "tolerations": [[{"key": "dedicated", "operator": "Equal", "value": "monitoring", "effect": "NoSchedule"}]],
    "affinity": [
        {},
        {
            "nodeAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": {
                    "nodeSelectorTerms": [
                        {"matchExpressions": [{"key": "kubernetes.io/arch", "operator": "In", "values": ["arm64"]}]}
                    ]
                }
            }
        },
    ],
}

# Values a property only takes effect with, merged into both the case and its baseline.
CONTEXT = {"caCerts": {"enabled": True}}

# Where each string-map property must show up in the rendered manifests.
STRING_MAP_TARGETS = {
    "podLabels": lambda docs: [pod_template(docs)["metadata"]["labels"]],
    "podAnnotations": lambda docs: [pod_template(docs)["metadata"].get("annotations") or {}],
    "additionalLabels": lambda docs: [d["metadata"].get("labels") or {} for d in docs],
    "nodeSelector": lambda docs: [pod_template(docs)["spec"].get("nodeSelector") or {}],
}
# Pod labels the chart owns; a user value for these is ignored by design.
RESERVED_POD_LABELS = {"name"}


def daemonset(docs):
    return next(d for d in docs if d["kind"] == "DaemonSet")


def pod_template(docs):
    return daemonset(docs)["spec"]["template"]


def as_string(value):
    return json.dumps(value) if isinstance(value, bool) else str(value)


def types_of(schema):
    t = schema.get("type", [])
    return set(t if isinstance(t, list) else [t])


def string_map_sample(value_schema):
    if value_schema.get("type") == "string":
        return {k: "value" for k in TRICKY_KEYS}
    sample = {k: "value" for k in TRICKY_KEYS}
    sample.update({"example.com/number": 12345, "example.com/big-number": 12345678, "example.com/flag": True})
    return sample


def samples_for(path, schema):
    """Returns sample values for a leaf property, or None if it has sub-properties."""
    if path[-1] in SAMPLES and len(path) == 1:
        return SAMPLES[path[-1]]
    if "enum" in schema:
        return list(schema["enum"])
    types = types_of(schema)
    if "properties" in schema:
        return None
    if "object" in types and isinstance(schema.get("additionalProperties"), dict):
        return [string_map_sample(schema["additionalProperties"])]
    if "boolean" in types:
        return [True, False]
    if "integer" in types:
        return sorted({schema.get("minimum", 1), schema.get("maximum", schema.get("minimum", 1) + 1)})
    if "string" in types:
        return ["test-value"]
    raise ValueError(f"No sample for {'.'.join(path)}: add one to SAMPLES")


def leaf_properties(schema, path=()):
    for name, prop in schema.get("properties", {}).items():
        sub = path + (name,)
        values = samples_for(sub, prop)
        if values is None:
            yield from leaf_properties(prop, sub)
        else:
            yield sub, prop, values


def with_value(base, path, value):
    values = copy.deepcopy(base)
    node = values
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value
    return values


def merge(a, b):
    out = copy.deepcopy(a)
    for k, v in b.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def render(chart, values):
    result = subprocess.run(
        ["helm", "template", "nfm", chart, "--namespace", NAMESPACE, "--values", "-"],
        input=json.dumps(values),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.strip())
    return result.stdout, [d for d in yaml.safe_load_all(result.stdout) if d]


def check_string_maps(docs):
    for obj in docs + [pod_template(docs)]:
        for field in ("labels", "annotations"):
            for k, v in (obj["metadata"].get(field) or {}).items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise AssertionError(f"{obj.get('kind', 'Pod template')} {field} entry {k!r}: {v!r} is not a string pair")


def check_selector(docs):
    ds = daemonset(docs)
    selector = ds["spec"]["selector"]["matchLabels"]
    expected = {"name": ds["metadata"]["name"]}
    if selector != expected:
        raise AssertionError(f"DaemonSet selector {selector} must stay {expected}; it can't change after install")
    labels = pod_template(docs)["metadata"]["labels"]
    if any(labels.get(k) != v for k, v in selector.items()):
        raise AssertionError(f"Pod template labels {labels} don't match the selector {selector}")


def check_reflected(path, value, docs):
    if len(path) != 1 or path[0] not in STRING_MAP_TARGETS:
        return
    for target in STRING_MAP_TARGETS[path[0]](docs):
        for k, v in value.items():
            if path[0] == "podLabels" and k in RESERVED_POD_LABELS:
                continue
            if target.get(k) != as_string(v):
                raise AssertionError(f"{path[0]} entry {k!r}: {v!r} rendered as {target.get(k)!r}")


def check_manifests(docs, values):
    check_string_maps(docs)
    check_selector(docs)
    for name, value in values.items():
        if isinstance(value, dict):
            check_reflected((name,), value, docs)


def test_values_files(chart, files):
    failures = []
    for path in files:
        with open(path) as f:
            values = merge(EKS_VALUES, yaml.safe_load(f) or {})
        try:
            _, docs = render(chart, values)
            check_manifests(docs, values)
            print(f"PASS {path}")
        except AssertionError as e:
            failures.append(path)
            print(f"FAIL {path}: {e}")
    print(f"{len(files)} values files, {len(failures)} failing")
    return failures


def test_schema(chart, schema):
    failures = []
    combined = copy.deepcopy(EKS_VALUES)
    cases = 0
    for path, prop, values in leaf_properties(schema):
        name = ".".join(path)
        context = merge(EKS_VALUES, {path[0]: CONTEXT[path[0]]}) if path[0] in CONTEXT else EKS_VALUES
        try:
            baseline, _ = render(chart, context)
            changed = False
            for value in values:
                cases += 1
                text, docs = render(chart, with_value(context, path, value))
                check_manifests(docs, {})
                check_reflected(path, value, docs)
                changed = changed or text != baseline
            if not changed and not prop.get("deprecated"):
                raise AssertionError("no sample value changes the rendered manifests; the chart ignores it")
            combined = with_value(merge(combined, context), path, values[-1])
            print(f"PASS {name}")
        except AssertionError as e:
            failures.append(name)
            print(f"FAIL {name}: {e}")

    try:
        _, docs = render(chart, combined)
        check_manifests(docs, combined)
        print("PASS all properties together")
    except AssertionError as e:
        failures.append("all properties together")
        print(f"FAIL all properties together: {e}")

    print(f"{cases} cases, {len(failures)} failing properties")
    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chart", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--schema")
    mode.add_argument("--values", nargs="+")
    args = parser.parse_args()

    if args.schema:
        with open(args.schema) as f:
            failures = test_schema(args.chart, json.load(f))
    else:
        failures = test_values_files(args.chart, args.values)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
