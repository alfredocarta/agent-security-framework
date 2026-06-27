#!/usr/bin/env python3
from __future__ import annotations
import json, pathlib, sys, os, re
ROOT=pathlib.Path(__file__).resolve().parents[2]
out_dir=pathlib.Path(os.environ.get("ASF_EQUIV_OUT", ROOT/"tests/equivalence/out"))
py=out_dir/"py_canonical.jsonl"; rs=out_dir/"rust_canonical.jsonl"
BOUNDARY_OPS={"security_interceptor","hardened_interceptor"}
TERMINAL={"ALLOW","DENY"}
FORWARD_RE=re.compile(r"forward_to_python_stage23|stage1_no_match_forward_to_python_stage23", re.I)

def load(p):
    rows=[]
    if not p.exists(): return rows
    for i,l in enumerate(p.read_text(encoding="utf-8").splitlines(),1):
        if l.strip():
            r=json.loads(l); r['_line']=i; rows.append(r)
    return rows

def key(r): return (r['op'], r['input_id'])
pyrows, rsrows=load(py), load(rs)
# dedupe repeated instrumentation: compare first record per op/input/outcome boundary.
def first_map(rows):
    m={}
    for r in rows: m.setdefault(key(r), r)
    return m
pm,rm=first_map(pyrows),first_map(rsrows)
allk=sorted(set(pm)|set(rm))
match=[]; mismatch=[]; only_py=[]; only_rs=[]; out_of_scope=[]

def is_boundary_out_of_scope(k, rust_row):
    if k[0] not in BOUNDARY_OPS or rust_row is None:
        return False
    out=rust_row.get('out') or {}
    verdict=str(out.get('verdict','')).upper()
    reason=str(out.get('reason',''))
    return verdict not in TERMINAL or FORWARD_RE.search(reason) is not None

for k in allk:
    if k not in pm:
        if is_boundary_out_of_scope(k, rm.get(k)):
            out_of_scope.append(rm[k])
        else:
            only_rs.append(rm[k])
        continue
    if k not in rm:
        only_py.append(pm[k]); continue
    if is_boundary_out_of_scope(k, rm[k]):
        out_of_scope.append((pm[k],rm[k])); continue
    if pm[k]['out']==rm[k]['out']: match.append(k)
    else: mismatch.append((pm[k],rm[k]))

print("Canonical equivalence summary")
print("kind                           count")
print(f"MATCH                          {len(match)}")
print(f"MISMATCH                       {len(mismatch)}")
print(f"ONLY_IN_PY                     {len(only_py)}")
print(f"ONLY_IN_RUST                   {len(only_rs)}")
print(f"OUT_OF_SCOPE                   {len(out_of_scope)}")
if mismatch:
    print("\nMISMATCH details:")
    for a,b in mismatch[:50]:
        print(f"- op={a['op']} input_id={a['input_id']} input={a.get('input','')[:120]!r}")
        keys=sorted(set(a['out'])|set(b['out']))
        for kk in keys:
            if a['out'].get(kk)!=b['out'].get(kk): print(f"  {kk}: py={a['out'].get(kk)!r} rust={b['out'].get(kk)!r}")
if only_py:
    print("\nONLY_IN_PY:")
    for r in only_py[:50]: print(f"- op={r['op']} input_id={r['input_id']} input={r.get('input','')[:120]!r}")
if only_rs:
    print("\nONLY_IN_RUST:")
    for r in only_rs[:50]: print(f"- op={r['op']} input_id={r['input_id']} input={r.get('input','')[:120]!r}")
if out_of_scope:
    print("\nOUT_OF_SCOPE boundary forwards:")
    for r in out_of_scope[:20]:
        rr=r[1] if isinstance(r, tuple) else r
        print(f"- op={rr['op']} input_id={rr['input_id']} rust_verdict={rr.get('out',{}).get('verdict')!r} reason={rr.get('out',{}).get('reason')!r}")

# Pattern divergence report. Representation divergence is normalized separately from
# true engine divergence: inline (?i) and Python re.IGNORECASE are equivalent.
def norm_pat(row, side):
    pat=row.get('pattern','')
    ignore=bool(row.get('py_ignorecase')) if side=='py' else False
    body=pat
    m=re.match(r"^\(\?([a-zA-Z]+)\)", body)
    if m:
        ignore = ignore or ('i' in m.group(1))
        body=body[m.end():]
    elif body.startswith('(?i)'):
        ignore=True
        body=body[4:]
    # Normalize representation-only escapes emitted differently by Python raw strings
    # and Rust raw strings. These do not change regex semantics in either engine.
    body=body.replace(r"\/", "/").replace(r"\'", "'")
    return (row.get('source'), body, ignore)

critical=[]; true_regex=[]
pp=out_dir/'py_patterns.json'; rp=out_dir/'rust_patterns.json'
if pp.exists() and rp.exists():
    py_list=json.loads(pp.read_text(encoding='utf-8'))
    rs_list=json.loads(rp.read_text(encoding='utf-8'))
    pyps={norm_pat(x,'py'):x for x in py_list}
    rsps={norm_pat(x,'rs'):x for x in rs_list}
    for k,pv in pyps.items():
        rv=rsps.get(k)
        if not rv:
            critical.append((k,'missing_rust_pattern_after_normalization',pv,None)); continue
        # True regex divergence: Python compiles but Rust cannot, or match sets differ.
        if pv.get('py_compiles') and not rv.get('rust_compiles'):
            true_regex.append((k,'python_compiles_rust_fails',pv,rv))
        elif pv.get('py_compiles') and rv.get('rust_compiles') and pv.get('py_matches') != rv.get('rust_matches'):
            true_regex.append((k,'different_match_set',pv,rv))
    for k,rv in rsps.items():
        if k not in pyps:
            critical.append((k,'missing_python_pattern_after_normalization',None,rv))
print(f"\nCRITICAL_PATTERN_DIVERGENCE     {len(critical)}")
for (src,body,ignore),why,pv,rv in critical[:50]:
    shown=(pv or rv).get('pattern')
    print(f"- {why} source={src} ignorecase={ignore} pattern={shown!r}")
print(f"TRUE_REGEX_DIVERGENCE          {len(true_regex)}")
for (src,body,ignore),why,pv,rv in true_regex[:50]:
    print(f"- {why} source={src} ignorecase={ignore} pattern={pv.get('pattern')!r}")
    if rv and rv.get('rust_error'): print(f"  rust_error={rv['rust_error']}")
    if rv: print(f"  py_matches={pv.get('py_matches')} rust_matches={rv.get('rust_matches')}")
raise SystemExit(1 if mismatch or only_py or only_rs or critical or true_regex else 0)
