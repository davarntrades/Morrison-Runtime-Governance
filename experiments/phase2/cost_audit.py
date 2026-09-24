"""Read-only terminal usage of completed Phase 2 CMA sessions."""
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from experiments.phase2 import campaign as c


def main():
    targets=json.loads(Path('experiments/phase2/cost_targets.json').read_text())
    out=[]
    for t in targets:
        code,res,rid=c.anthropic('GET',f"/sessions/{t['session']}")
        usage=res.get('usage') if code==200 else None
        out.append({**t,'http_status':code,'request_id':rid,'status':res.get('status'),
            'terminal_model':(res.get('agent') or {}).get('model'),'usage':usage,
            'list_cost_cents':(usage or {}).get('list_cost',{}).get('amount')})
        print(t['run'],t['family'],t['trial'],code,flush=True)
    (c.ROOT/'terminal-cost.json').write_text(json.dumps(out,indent=2))


if __name__=='__main__':main()
