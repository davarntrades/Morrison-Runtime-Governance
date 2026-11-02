# Exact commands that produced this directory (at commit fe83313); scratch paths generalised.
set -x
cd /home/user/Morrison-Runtime-Governance
export BENCH_WORKDIR=${BENCH_WORKDIR:-/tmp/mrg-bench} PYTHONPATH=.
R=benchmarks/performance/results-remediation
mkdir -p $R
L="python3 -m benchmarks.performance.load --out $R"
$L --model threads --mode inprocess --session isolated --policy default --levels 1,4,16,64,256
$L --model threads --mode inprocess --session isolated --policy default --approve-prohibited --levels 1,16,64
$L --model threads --mode inprocess --session isolated --policy hard-deny --approve-prohibited --levels 1,16,64
$L --model threads --mode inprocess --session session --policy default --levels 1,16,128
$L --model threads --mode inprocess --session session --policy hard-deny --approve-prohibited --levels 1,16,128
$L --model threads --mode mediated --session isolated --policy default --levels 1,16,64
$L --model processes --mode inprocess --session isolated --policy default --levels 1,4,16
python3 -m benchmarks.performance.e2e --ops 2000 --levels 1,4,16,64 --out $R
python3 -m benchmarks.performance.falsify_remediation --out $R --tlc ${TLC_JAR:?set TLC_JAR to tla2tools.jar}
python3 -m benchmarks.performance.profile_history --out $R
python3 -m benchmarks.performance.corrected_accounting --out $R > $R/corrected-accounting-frozen.txt
for esc in deny deny-and-approve; do rm -rf /tmp/mrg-tla-$esc; python3 -m morrison_governance.global_verification.tla_export --out /tmp/mrg-tla-$esc --escalations $esc --tlc ${TLC_JAR:?set TLC_JAR to tla2tools.jar}; cp /tmp/mrg-tla-$esc/crosscheck.json $R/tla-crosscheck-$esc.json; done
rm -rf /tmp/mrg-repro-post; mkdir -p /tmp/mrg-repro-post
python3 benchmarks/performance/review_repro/repro_tlc_false_success.py /tmp/mrg-tla-deny ${TLC_JAR:?set TLC_JAR to tla2tools.jar} /tmp/mrg-repro-post 2>&1 | grep -v JAVA_TOOL > $R/tlc-false-success-post-repair.json
gzip -f $R/*-raw.json
echo REGRESSION-DONE
