"""Score, sound design and voiceover mix for cinema.html.

    python3 cinema_audio.py film-silent.cues.json vo/ out.wav

Reads the cue list the renderer exports (render.js writes <out>.cues.json) so
picture and sound share one timeline. Everything is synthesised; the voice is
Piper TTS (en_US ryan-high) rendered into vo/v1..v7.wav beforehand.
"""
import json, os, sys, wave
import numpy as np
from scipy.signal import butter, sosfilt, fftconvolve

SR = 48000
rng = np.random.default_rng(11)
cues_path, vo_dir, out_path = sys.argv[1:4]
spec = json.load(open(cues_path))
TOTAL, CUES = spec["total"], spec["cues"]
N = int(SR * (TOTAL + 1.0))
t_all = np.arange(N) / SR
at = {}
for c in CUES:
    at.setdefault(c[1], []).append(c[0])
VO = {c[2]: c[0] for c in CUES if c[1] == "vo"}
first = lambda k: at[k][0]


def lp(sig, f, order=2):
    return sosfilt(butter(order, f, "low", fs=SR, output="sos"), sig)


def hp(sig, f, order=2):
    return sosfilt(butter(order, f, "high", fs=SR, output="sos"), sig)


def bp(sig, lo, hi, order=2):
    return sosfilt(butter(order, [lo, hi], "band", fs=SR, output="sos"), sig)


def T(d):
    return np.arange(int(SR * d)) / SR


def env(times, vals):
    """piecewise-linear gain curve over the whole timeline"""
    return np.interp(t_all, times, vals)


def place(buf, sig, t0, g=1.0):
    i = int(SR * t0)
    j = min(len(buf), i + len(sig))
    if 0 <= i < len(buf):
        buf[i:j] += g * sig[: j - i]


# ── the score: string-like pads, section by section ────────────────────────
def pad(freqs, t0, t1, att=2.0, rel=1.5, bright=900, hard_end=False):
    d = t1 - t0 + (0 if hard_end else rel)
    t = T(d)
    s = np.zeros_like(t)
    for f in freqs:
        for det in (-0.0023, 0.0, 0.0021):
            ph = rng.uniform(0, 6.28)
            vib = 1 + 0.0018 * np.sin(2 * np.pi * (4.7 + rng.uniform(-.4, .4)) * t + ph)
            for h in range(1, 8):
                s += np.sin(2 * np.pi * f * (1 + det) * h * np.cumsum(vib) / SR + ph * h) / h ** 1.35
    s = lp(s, bright)
    e = np.minimum(1, t / att)
    if not hard_end:
        e *= np.clip((d - t) / rel, 0, 1)
    return s * e / (len(freqs) * 3)


music = np.zeros(N)
A1, E2, A2, C3, D2, F2, Bb2, Cs3, E3, A3 = 55, 82.41, 110, 130.81, 73.42, 87.31, 116.54, 138.59, 164.81, 220
T2, T3, T4, T5, T6 = first("space2"), first("mech"), first("lab"), at["space2"][1], first("space3")
CUT, FREEZE, FB = first("cut"), first("freeze"), first("finalblock")

# 1 · the meteor: low strings grow, then the hard cut
place(music, pad([A1, E2, A2, C3], 0.4, CUT, att=5, bright=700, hard_end=True), 0.4, 1.0)
place(music, pad([A3 * 2], 3.6, CUT, att=3, bright=2400, hard_end=True), 3.6, 0.10)
# 2 · the core: minor, a dissonant Bb creeps in at the red branch, collapses at the freeze
place(music, pad([D2, F2, A2], T2, FREEZE, att=2.5, rel=.25), T2, 0.9)
place(music, pad([Bb2, Bb2 * 2], first("redpulse"), FREEZE, att=1.2, rel=.2, bright=1400), first("redpulse"), 0.55)
place(music, pad([D2, A2], FREEZE + .1, T3, att=.6, rel=.8, bright=500), FREEZE + .1, 0.35)
# 3 · architecture: sparse, low, precise
place(music, pad([A1, E2], T3, T4, att=1.5, rel=.1, bright=500, hard_end=True), T3, 0.45)
# 4 · evidence: almost dry — a faint bed only
place(music, pad([A1, E2, A2], T4 + 1.5, T5, att=3, rel=.8, bright=400), T4 + 1.5, 0.22)
# 5 · the principle: resolves, calm and certain
place(music, pad([A2, Cs3, E3], T5, T6, att=1.5, rel=1.0, bright=1100), T5, 0.6)
# 6 · final callback: tension up to the block, then silence; a low chord under the title
place(music, pad([A1, E2, Bb2 / 2 * 1.0, A2], T6, FB, att=1.8, bright=800, hard_end=True), T6, 0.8)
place(music, pad([A1, E2, A2], first("title"), TOTAL, att=2.5, rel=.8, bright=600), first("title"), 0.35)

# sub-bass under the approaching meteor (both times), cut at the cut / the block
sub = np.zeros(N)
for s0, s1, g in ((3.6, CUT, .22), (T6, FB, .12)):
    t = T(s1 - s0)
    f = 34 + 10 * (t / t[-1])
    place(sub, np.sin(2 * np.pi * np.cumsum(f) / SR) * (t / t[-1]) ** 1.6, s0, g)

# space ambience: dark air, off in the lab and after the final block
air = lp(rng.standard_normal(N), 380) * 0.9
air *= env([0, 1, CUT - .01, CUT, T2, T2 + .8, T4 - .01, T4, T5, T5 + .8, FB - .01, FB, TOTAL],
           [0, .12, .12, 0, 0, .10, .10, 0, 0, .09, .09, .012, 0])
room = lp(hp(rng.standard_normal(N), 60), 220) * env([T4, T4 + .5, T5 - .3, T5], [0, .05, .05, 0])

# ── sound design ────────────────────────────────────────────────────────────
fx = np.zeros(N)


def impact(depth=1.0, tail=1.0):
    t = T(2.2 * tail)
    f = 40 + 26 * np.exp(-t * 9)
    body = np.sin(2 * np.pi * np.cumsum(f * depth) / SR) * np.exp(-t / (0.42 * tail))
    thump = lp(rng.standard_normal(len(t)), 220) * np.exp(-t / 0.05) * 2.2
    clamp_ = sum(np.sin(2 * np.pi * p * t) for p in (1210, 1935, 3090)) * np.exp(-t / 0.07) * 0.05
    return np.tanh(1.3 * (body + thump + clamp_))


def click():
    t = T(0.05)
    return hp(rng.standard_normal(len(t)), 1800) * np.exp(-t / 0.004) * .8 + np.sin(2 * np.pi * 2900 * t) * np.exp(-t / 0.006) * .4


def servo(d=0.55):
    t = T(d)
    f = 180 + 260 * (t / d) ** .6
    return np.sin(2 * np.pi * np.cumsum(f) / SR) * np.sin(np.pi * t / d) ** 2 * .35 + bp(rng.standard_normal(len(t)), 800, 2400) * np.sin(np.pi * t / d) ** 2 * .08


def sweep(d=0.8):
    t = T(d)
    n = rng.standard_normal(len(t))
    out = np.zeros_like(t)
    seg = len(t) // 8
    for k in range(8):  # stepped band-pass sweep
        lo = 400 * 1.35 ** k
        out[k * seg:(k + 1) * seg] = bp(n, lo, lo * 1.8)[k * seg:(k + 1) * seg]
    return out * np.sin(np.pi * t / d) ** 2 * .5


def chime():
    t = T(1.6)
    return (np.sin(2 * np.pi * 2350 * t) + .5 * np.sin(2 * np.pi * 3525 * t)) * np.exp(-t / .45) * np.minimum(1, t / .01) * .25


def blip():
    t = T(0.09)
    s = np.sin(2 * np.pi * 1250 * t) * np.exp(-t / .02)
    return np.concatenate([s, np.zeros(int(.05 * SR)), s * .7]) * .35


def soft():
    t = T(1.2)
    return np.sin(2 * np.pi * 49 * t) * np.exp(-t / .3) * np.minimum(1, t / .02) * .7


def riser(d):
    t = T(d)
    n, k = rng.standard_normal(len(t)), (t / d) ** 2      # opens up as it rises
    return ((1 - k) * lp(n, 300) + k * lp(n, 3800)) * (t / d) ** 2.4 * .5


for t0 in at.get("glint", []): place(fx, chime(), t0, .7)
for t0 in at.get("swell", []): place(fx, riser(CUT - t0)[: int(SR * (CUT - t0))], t0, .5)
for t0 in at.get("redpulse", []):
    place(fx, soft(), t0, .9); place(fx, soft(), t0 + .45, .7)
for t0 in at.get("freeze", []):
    t = T(.4); place(fx, np.sin(2 * np.pi * np.cumsum(260 * np.exp(-t * 5) + 30) / SR) * np.exp(-t / .15) * .5, t0)
for t0 in at.get("reveal", []): place(fx, impact(.8, .8), t0, .35); place(fx, chime(), t0 + .05, .35)
for t0 in at.get("click", []): place(fx, click(), t0, .8)
for t0 in at.get("servo", []): place(fx, servo(), t0, .8)
for t0 in at.get("scan", []): place(fx, sweep(), t0, .8)
for t0 in at.get("block", []): place(fx, impact(), t0, .7)
for t0 in at.get("blip", []): place(fx, blip(), t0)
for t0 in at.get("paper", []): place(fx, sweep(.45), t0, .6)
for t0 in at.get("count", []):
    for k in range(12): place(fx, click(), t0 + k * .075, .18)
for t0 in at.get("tick", []): place(fx, click(), t0, .15)
for t0 in at.get("soft", []): place(fx, soft(), t0, .8)
for t0 in at.get("finalblock", []): place(fx, impact(.9, 1.6), t0, 1.0)
for t0 in at.get("title", []): place(fx, chime(), t0, .3)

# ── voiceover ───────────────────────────────────────────────────────────────
voice = np.zeros(N)
for vid, t0 in VO.items():
    w = wave.open(os.path.join(vo_dir, vid + ".wav"))
    sr0 = w.getframerate()
    a = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(float) / 32768
    a = np.interp(np.arange(0, len(a) / sr0, 1 / SR), np.arange(len(a)) / sr0, a)
    a = hp(a, 85)
    a = a + 0.25 * bp(a, 2500, 6000)            # a little presence
    a = np.tanh(2.2 * a) / np.tanh(2.2)           # gentle compression
    place(voice, a, t0, 0.9)
vo_env = np.convolve((np.abs(voice) > 0.02).astype(float), np.ones(int(.35 * SR)) / int(.35 * SR), "same")
duck = 1 - 0.55 * np.clip(vo_env * 3, 0, 1)

# ── mix ─────────────────────────────────────────────────────────────────────
# the final block lands into near-silence: everything but the voice falls away at FB
after = env([0, FB - .05, FB + .25, first("title"), first("title") + 2, TOTAL], [1, 1, .06, .06, 1, 1])
bed = (music * 0.55 + sub + air + room) * duck * after
mix_dry = bed + fx * 0.7 * np.where(t_all >= FB + .05, 1.0, after) + voice


def ir(seed, d=2.4):
    r = np.random.default_rng(seed)
    t = T(d)
    return lp(r.standard_normal(len(t)), 5200) * np.exp(-t / .55) * 0.12


wetL = fftconvolve(bed + fx * .7 + voice * .35, ir(1))[:N]
wetR = fftconvolve(bed + fx * .7 + voice * .35, ir(2))[:N]
L = mix_dry + wetL * .6
R = mix_dry + wetR * .6
st = np.stack([L, R], 1)
st *= env([0, TOTAL - .8, TOTAL], [1, 1, 0])[:, None]
# master: set loudness from a voiced section (voice + bed ≈ -16 dBFS RMS), then soft-limit peaks
ref = st[int(T3 * SR):int(T4 * SR)]
st *= 10 ** (-16 / 20) / np.sqrt(np.mean(ref ** 2))
k, span = .72, .24
mag = np.abs(st)
st = np.where(mag > k, np.sign(st) * (k + span * np.tanh((mag - k) / span)), st)
pcm = (st * 32767).astype(np.int16)
with wave.open(out_path, "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR); w.writeframes(pcm.tobytes())
print(f"{out_path}: {len(pcm) / SR:.1f}s")
