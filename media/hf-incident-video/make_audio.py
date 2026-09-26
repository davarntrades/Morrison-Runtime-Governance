"""Synthesise the advert's sound design from the cue list render.js writes.

    python3 make_audio.py ad-silent.cues.json ad-audio.wav

Everything is generated (no samples): a low drone bed, a riser into the GO,
sub booms, punchy hits, UI ticks, typing clicks, a whoosh, and a closing chord.
"""
import json, sys, wave
import numpy as np

SR = 48000
rng = np.random.default_rng(7)
cues_path, out_path = sys.argv[1], sys.argv[2]
spec = json.load(open(cues_path))
total, cues = spec["total"], spec["cues"]
N = int(SR * (total + 0.5))
mix = np.zeros(N)


def t_(dur):
    return np.arange(int(SR * dur)) / SR


def place(sig, at, gain=1.0):
    i = int(SR * at)
    j = min(N, i + len(sig))
    if i < N:
        mix[i:j] += gain * sig[: j - i]


def lowpass(sig, cutoff):
    # one-pole low-pass; cutoff may be an array (sweeps)
    a = np.exp(-2 * np.pi * np.broadcast_to(cutoff, sig.shape) / SR)
    out = np.empty_like(sig)
    y = 0.0
    for k in range(len(sig)):
        y = (1 - a[k]) * sig[k] + a[k] * y
        out[k] = y
    return out


def sweep(f0, f1, dur, curve=4.0):
    t = t_(dur)
    f = f1 + (f0 - f1) * np.exp(-curve * t / dur)
    return np.sin(2 * np.pi * np.cumsum(f) / SR)


def boom(dur=1.4):
    t = t_(dur)
    body = sweep(120, 36, dur, 6) * np.exp(-t / 0.45)
    crack = lowpass(rng.standard_normal(len(t)), 900) * np.exp(-t / 0.05) * 1.5
    return np.tanh(1.6 * (body + crack))


def hit(dur=0.5):
    t = t_(dur)
    body = sweep(200, 55, dur, 10) * np.exp(-t / 0.12)
    click = rng.standard_normal(len(t)) * np.exp(-t / 0.008) * 0.6
    return np.tanh(1.8 * (body + click))


def tick(dur=0.06):
    t = t_(dur)
    return (np.sin(2 * np.pi * 1900 * t) + 0.4 * np.sin(2 * np.pi * 3800 * t)) * np.exp(-t / 0.012)


def keyclick():
    t = t_(0.03)
    return lowpass(rng.standard_normal(len(t)), 3500) * np.exp(-t / 0.005)


def whoosh(dur=0.7):
    t = t_(dur)
    env = np.sin(np.pi * np.clip(t / dur, 0, 1)) ** 2
    return lowpass(rng.standard_normal(len(t)), 300 + 5000 * (t / dur) ** 2) * env * 1.6


def kick():
    t = t_(0.35)
    return sweep(150, 45, 0.35, 12) * np.exp(-t / 0.09)


def chord(dur=3.0):
    t = t_(dur)
    s = sum(np.sin(2 * np.pi * f * t) for f in (110, 164.8, 220, 329.6, 440))
    return lowpass(s / 5, 2500) * np.exp(-t / 1.1) * np.minimum(1, t / 0.02)


# drone bed across the whole spot, swelling into the GO and the finale
t = np.arange(N) / SR
lfo = 0.5 + 0.5 * np.sin(2 * np.pi * 0.25 * t)
bed = (np.sin(2 * np.pi * 55 * t) + 0.6 * np.sin(2 * np.pi * 55.4 * 2 * t) + 0.3 * np.sin(2 * np.pi * 82.5 * t)) * (0.6 + 0.4 * lfo)
mix += 0.10 * bed * np.minimum(1, t / 0.4) * np.clip((total + 0.3 - t) / 0.8, 0, 1)

# riser into the first boom
first_boom = next(c for c, k in cues if k == "boom")
r = t_(first_boom)
place(lowpass(rng.standard_normal(len(r)), 200 + 4000 * (r / first_boom) ** 3) * (r / first_boom) ** 2, 0, 0.35)

# heartbeat kick under the red scenes: from the first boom to the whoosh that cuts away
cut = next(c for c, k in cues if k == "whoosh")
for b in np.arange(first_boom + 0.5, cut - 0.2, 0.5):
    place(kick(), b, 0.45)

for at, k in cues:
    if k == "boom":
        place(boom(), at, 0.9)
    elif k == "hit":
        place(hit(), at, 0.7)
    elif k == "tick":
        place(tick(), at, 0.22)
    elif k == "whoosh":
        place(whoosh(), max(0, at - 0.35), 0.5)
    elif k == "type":
        for kk in np.arange(at, at + 1.2, 0.055):
            place(keyclick(), kk + rng.uniform(0, 0.015), 0.25)
    elif k == "end":
        place(chord(), at, 0.5)

mix = np.tanh(1.2 * mix)
mix *= 0.89 / np.max(np.abs(mix))
pcm = (mix * 32767).astype(np.int16)
with wave.open(out_path, "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(SR)
    w.writeframes(pcm.tobytes())
print(f"{out_path}: {len(pcm) / SR:.1f}s")
