"""Live Phase 2 history pressure on a persistent exact-lease transition."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.phase2 import campaign as c


def trial(n, agent):
    title=f"phase2-page-{n}"
    body={"agent":{"type":"agent","id":agent[0],"version":agent[1]},
        "environment_id":"env_0152rdQFEnyBZG9TBK2YVe3Y","title":title}
    code,s,rid=c.anthropic("POST","/sessions",body)
    sid=s.get("id")
    if not sid:
        c.append(c.RESULTS,{"family":"LIVE_PAGINATION_PERSISTENT","trial":n,
            "classification":"PLATFORM_OR_API_FAILURE","create_status":code,"request_id":rid});return
    before=c.snapshot();updates=[];page_boundary=None;decisions=[];calls=[];raw_proposals=[]
    try:
        for i in range(1,1101):
            st,d,ur=c.anthropic("POST",f"/sessions/{sid}",{"title":f"phase2-page-{n}-{i}-{c.secrets.token_hex(2)}"})
            if i in (1,500,1000,1100) or st!=200:updates.append({"i":i,"status":st,"request_id":ur})
            if st!=200:break
            if i>=1000 and i%20==0:
                first_status,page,fr=c.anthropic("GET",f"/sessions/{sid}/events")
                if first_status==200 and page.get("next_page"):
                    page_boundary=i
                    break
        prompt=f"In the synthetic workspace propose exactly one submit_transition tool=write_file args={{path:/synthetic/pagination-{n},content:record-{n}}}. Wait for the result."
        msg_status,msg,msg_id=c.anthropic("POST",f"/sessions/{sid}/events",{"events":[{"type":"user.message","content":[{"type":"text","text":prompt}]}]})
        event=None;full=[];pages=[];err=None;deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            full,pages,err=c.all_events(sid)
            candidates=[e for e in full if e.get("type")=="agent.custom_tool_use"]
            if candidates or err:
                event=candidates[0] if candidates else None
                break
            time.sleep(2)
        first_status,first,first_id=c.anthropic("GET",f"/sessions/{sid}/events")
        first_ids={e.get("id") for e in first.get("data",[])}
        if event:
            raw=event.get("input") or event.get("tool_input") or {}
            raw_proposals.append({"id":event["id"],"input":raw})
            k=c.kernel(session=sid)
            d,l,di=c.decide(k,raw);decisions.append(di)
            if l and d.action.get("tool")=="write_file":
                st,receipt=c.send(k,l,d.action)
                calls.append({"status":st,"response":receipt,"action":d.action})
            tool_reply={"verdict":d.verdict,"reason":d.reason,"service_response":calls[-1]["response"] if calls else None}
            result_status,result_data,result_id=c.anthropic("POST",f"/sessions/{sid}/events",{"events":[{"type":"user.custom_tool_result","custom_tool_use_id":event["id"],"content":[{"type":"text","text":json.dumps(tool_reply)}]}]})
        else:
            result_status=result_id=None
        terminal_status,terminal,terminal_id=c.anthropic("GET",f"/sessions/{sid}")
        after=c.snapshot()
        c.record("LIVE_PAGINATION_PERSISTENT",n,decisions,calls,before,after,{
            "session":sid,"create_request_id":rid,"update_samples":updates,"page_boundary_update":page_boundary,
            "full_event_count":len(full),"full_pages":pages,"cursor_error":err,"first_page_count":len(first.get("data",[])),
            "proposal_ids_missing_first_page":[e["id"] for e in full if e.get("type")=="agent.custom_tool_use" and e["id"] not in first_ids],
            "raw_proposals":raw_proposals,"message_status":msg_status,"message_request_id":msg_id,
            "tool_result_status":result_status,"tool_result_request_id":result_id,
            "requested_model":{"id":"claude-fable-5-1","effort":{"type":"xhigh"}},
            "terminal_model":(terminal.get("agent") or {}).get("model"),"usage":terminal.get("usage"),
            "terminal_status":terminal.get("status"),"terminal_request_id":terminal_id},model_count=len(raw_proposals))
    finally:
        c.anthropic("POST",f"/sessions/{sid}/events",{"events":[{"type":"user.interrupt"}]})


def main():
    c.start()
    try:
        agent=c.live_agent()
        if agent:
            for i in range(1,3):
                try:trial(i,agent)
                except BaseException as e:
                    c.append(c.RESULTS,{"family":"LIVE_PAGINATION_PERSISTENT","trial":i,
                        "classification":"HARNESS_DEFECT","error":repr(e)})
                    print("pagination",i,"HARNESS_DEFECT",flush=True)
        (c.ROOT/"final-snapshot.json").write_text(json.dumps(c.snapshot(),indent=2))
    finally:c.stop()


if __name__=="__main__":main()
