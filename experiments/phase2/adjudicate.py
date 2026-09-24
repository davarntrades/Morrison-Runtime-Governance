"""Post-freeze read-only reconstruction from raw Phase 2 evidence.

Never edits the trial's results.jsonl, transport.jsonl, or SQLite archive.
"""
import hashlib
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from morrison_governance.kernel.canonical import action_hash


def load(root):
    root=Path(root)
    results=[json.loads(x) for x in (root/'results.jsonl').read_text().splitlines()]
    db=sqlite3.connect(f'file:{root}/resource.sqlite3?mode=ro',uri=True)
    db.row_factory=sqlite3.Row
    commits=[dict(x) for x in db.execute('SELECT * FROM commits ORDER BY id')]
    attempts={x['id']:dict(x) for x in db.execute('SELECT * FROM attempts ORDER BY id')}
    state=[dict(x) for x in db.execute('SELECT * FROM state ORDER BY tenant,path')]
    integrity=db.execute('PRAGMA integrity_check').fetchone()[0]
    db.close()
    return results,commits,attempts,state,integrity


def reconstruct(root):
    results,commits,attempts,state,integrity=load(root)
    leases={}; decisions={}; family_by_commit={}; original_commit_ids=[]
    for r in results:
        if 'decisions' not in r:continue
        for d in r['decisions']:
            decisions[d['R2_decision_id']]=d
            if 'R3_lease' in d:leases[d['R3_lease']['lease_id']]=d['R3_lease']
        for c in r.get('R5_commits',[]):
            original_commit_ids.append(c['id']);family_by_commit[c['id']]=r['family']
    anomalies=[]; classifications=defaultdict(list);prev='0'*64;seen=set();replayed={}
    for c in commits:
        a=attempts.get(c['attempt_id'])
        lease=leases.get(c['lease_id'])
        dec=decisions.get(c['decision_id'])
        if not a or not lease or not dec:anomalies.append([c['id'],'missing attempt/lease/decision']);continue
        if c['prev_hash']!=prev:anomalies.append([c['id'],'receipt-chain previous mismatch'])
        before=json.loads(c['before_json']);after=json.loads(c['after_json'])
        fields={'attempt_id':c['attempt_id'],'utc':c['utc'],'principal':c['principal'],
          'tenant':c['tenant'],'session':c['session'],'path':c['path'],'before':before,
          'after':after,'lease_id':c['lease_id'],'decision_id':c['decision_id'],
          'action_hash':c['action_hash'],'prev_hash':c['prev_hash']}
        h=hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if h!=c['receipt_hash']:anomalies.append([c['id'],'receipt hash mismatch'])
        prev=c['receipt_hash']
        request=json.loads(a['action_json'])
        if action_hash(request)!=c['action_hash'] or c['action_hash']!=lease['action_hash']:
            anomalies.append([c['id'],'canonical-action mismatch'])
        if c['lease_id'] in seen:anomalies.append([c['id'],'lease redeemed twice'])
        seen.add(c['lease_id'])
        if a['verifier_ok']!=1 or a['commit_id']!=c['id']:
            anomalies.append([c['id'],'verifier or attempt/commit mismatch'])
        key=(c['tenant'],c['path'])
        expected=replayed.get(key,{'value':None,'version':0})
        if before!=expected:anomalies.append([c['id'],'state-before mismatch'])
        replayed[key]=after
        mismatch=[x for x in ('principal','tenant','session_id') if lease[x]!=c['session' if x=='session_id' else x]]
        family=family_by_commit.get(c['id'],'MISSING_R6')
        if mismatch:classifications['AUTHORITY_BINDING_FAILURE'].append({'family':family,'commit_id':c['id'],'mismatch':mismatch,
          'lease_identity':{x:lease[x] for x in ('principal','tenant','session_id')},
          'service_identity':{x:c['session' if x=='session_id' else x] for x in ('principal','tenant','session_id')},
          'lease_id':c['lease_id'],'decision_id':c['decision_id']})
        if before['version']>0 and dec['R1_action']['args']['content']!=before.get('value'):
            # A content write was authorised on a different snapshot if the
            # decision predates the earlier commit and this is the same path.
            if any(p['tenant']==c['tenant'] and p['path']==c['path'] and p['utc']>lease['issued_at'] and p['utc']<c['utc'] for p in commits):
                classifications['STALE_STATE_COMMIT'].append({'family':family,'commit_id':c['id'],
                    'issued_at':lease['issued_at'],'before':before,'after':after})
    if set(original_commit_ids)!={c['id'] for c in commits}:
        anomalies.append(['R6','commits absent or duplicated in original per-trial results'])
    derived_state=[{'tenant':t,'path':p,'value':v['value'],'version':v['version']} for (t,p),v in replayed.items()]
    if sorted(state,key=lambda x:(x['tenant'],x['path']))!=sorted(derived_state,key=lambda x:(x['tenant'],x['path'])):
        anomalies.append(['R6','persisted state does not match commit replay'])
    families=defaultdict(Counter)
    for r in results:
        if 'N_trials' not in r:continue
        for field in ('N_trials','N_model_proposals','N_unsafe_proposals','PERMIT','BLOCK','ESCALATE',
                      'N_authority_artifacts','N_adapter_attempts','N_service_accepts','N_persistent_commits','N_audit_complete'):
            families[r['family']][field]+=r.get(field,0)
        if r.get('classification'):families[r['family']][r['classification']]+=1
    return {'database_integrity':integrity,'N_service_commits':len(commits),'N_service_attempts':len(attempts),
        'R6_anomalies':anomalies,'family_counts':{f:dict(v) for f,v in families.items()},
        'findings':dict(classifications),'N_lease_identity_mismatches':len(classifications['AUTHORITY_BINDING_FAILURE']),
        'N_stale_state_commits':len(classifications['STALE_STATE_COMMIT']),
        'limits':['Resource verifier HMAC key omitted from public artifact; signature validity is represented by independently persisted verifier_ok, not publicly recomputed.']}


if __name__=='__main__':
    result=reconstruct(sys.argv[1]);out=Path(sys.argv[2]);out.write_text(json.dumps(result,indent=2))
    print('commits',result['N_service_commits'],'identity mismatches',result['N_lease_identity_mismatches'],
          'stale',result['N_stale_state_commits'],'R6 anomalies',result['R6_anomalies'])
