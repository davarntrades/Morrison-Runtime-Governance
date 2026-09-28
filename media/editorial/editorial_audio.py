"""Light, upbeat bed + UI sound design for agent.html, built from the page's cues.

    python3 editorial_audio.py cues.json out.wav
    MOOD=tense python3 editorial_audio.py cues.json out.wav   # slower minor-key bed for news pieces
"""
import json, os, sys, wave
import numpy as np
from scipy.signal import butter, sosfilt

SR = 48000
rng = np.random.default_rng(3)
spec = json.load(open(sys.argv[1]))
TOTAL, CUES = spec["total"], spec["cues"]
N = int(SR * (TOTAL + .6))
out = np.zeros((N, 2))
T = lambda d: np.arange(int(SR * d)) / SR
lp = lambda s, f: sosfilt(butter(2, f, "low", fs=SR, output="sos"), s)
hp = lambda s, f: sosfilt(butter(2, f, "high", fs=SR, output="sos"), s)


def put(sig, t0, g=1.0, pan=0.0):
    i = int(SR * t0); j = min(N, i + len(sig))
    if 0 <= i < N:
        out[i:j, 0] += g * sig[: j - i] * (1 - pan) ** .5
        out[i:j, 1] += g * sig[: j - i] * (1 + pan) ** .5


def pluck(f, d=.45):
    t = T(d)
    s = sum(np.sin(2 * np.pi * f * h * t) * np.exp(-t * (6 + h * 3)) / h for h in (1, 2, 3, 4))
    return s * np.minimum(1, t / .004)


def kick():
    t = T(.3); return np.sin(2 * np.pi * np.cumsum(50 + 90 * np.exp(-t * 30)) / SR) * np.exp(-t * 11)


def clap():
    t = T(.18); return hp(rng.standard_normal(len(t)), 900) * np.exp(-t * 26) * .6


def hat():
    t = T(.05); return hp(rng.standard_normal(len(t)), 7000) * np.exp(-t * 90) * .35


def blip(f, d=.12):
    t = T(d); return np.sin(2 * np.pi * f * t) * np.exp(-t * 30)


def swoosh(d=.35):
    t = T(d); n = rng.standard_normal(len(t)); k = t / d
    return ((1 - k) * lp(n, 800) + k * lp(n, 5000)) * np.sin(np.pi * k) ** 2 * .5


TENSE = os.environ.get("MOOD") == "tense"
# beat: 112 bpm, I–V–vi–IV in C with a bright pluck arpeggio (tense: 96 bpm, i–VI–iv–V in A minor)
bpm = 96 if TENSE else 112; step = 60 / bpm / 2
chords = [[261.6, 329.6, 392.0, 523.3], [196.0, 246.9, 293.7, 392.0], [220.0, 261.6, 329.6, 440.0], [174.6, 220.0, 261.6, 349.2]]
bass = [65.4, 49.0, 55.0, 43.7]
if TENSE:
    chords = [[220.0, 261.6, 329.6, 440.0], [174.6, 220.0, 261.6, 349.2], [146.8, 174.6, 220.0, 293.7], [164.8, 207.7, 246.9, 329.6]]
    bass = [55.0, 43.7, 36.7, 41.2]
n_steps = int((TOTAL - .4) / step)
for k in range(n_steps):
    t0 = k * step; bar = (k // 8) % 4; ch = chords[bar]
    if k % 4 == 0: put(kick(), t0, .9)
    if k % 8 == 4: put(clap(), t0, .7)
    put(hat(), t0 + (step * .02 if k % 2 else 0), (.3 if k % 2 else .18) if TENSE else (.5 if k % 2 else .3), pan=.3)
    pl = pluck(ch[[0, 2, 1, 3, 2, 1, 3, 2][k % 8]] * 2, .4)
    put(lp(pl, 1800) if TENSE else pl, t0, .26 if TENSE else .22, pan=-.25 + .5 * (k % 2))
    if k % 8 == 0:
        t = T(step * 8); put(np.sin(2 * np.pi * bass[bar] * t) * np.exp(-t * 1.2) * np.minimum(1, t / .01), t0, .45)

at = {}
for t0, k in CUES: at.setdefault(k, []).append(t0)
for t0 in at.get("cut", []): put(swoosh(.3), t0 - .12, .5)
for t0 in at.get("pop", []) + at.get("card", []): put(blip(1320) + .5 * blip(1980), t0, .35, pan=.2)
for t0 in at.get("swoosh", []): put(swoosh(.4), t0, .45)
for t0 in at.get("type", []):
    for k in range(18): put(hp(rng.standard_normal(int(.02 * SR)), 2500) * np.exp(-T(.02) * 200), t0 + k * .07, .25)
for t0 in at.get("bubble", []): put(blip(880, .15) + blip(1320, .15), t0, .4)
for t0 in at.get("allow", []): put(blip(1046.5, .3) + blip(1568, .3), t0, .45)
for t0 in at.get("escalate", []): put(blip(740, .35) * np.sin(2 * np.pi * 6 * T(.35)) ** 2, t0, .5)
for t0 in at.get("block", []): put(np.sin(2 * np.pi * np.cumsum(140 * np.exp(-T(.35) * 6) + 60) / SR) * np.exp(-T(.35) * 8), t0, .9)
for t0 in at.get("count", []):
    for k in range(10): put(blip(1500 + k * 60, .05), t0 + k * .09, .2)
for t0 in at.get("thud", []): put(kick() * 1.2, t0, .9)
for t0 in at.get("resolve", []):
    t = T(2.2); put(sum(np.sin(2 * np.pi * f * t) for f in (261.6, 329.6, 392.0, 523.3)) * np.exp(-t * 1.4) * .25, t0, .6)

out *= np.interp(np.arange(N) / SR, [0, .15, TOTAL - .5, TOTAL], [0, 1, 1, 0])[:, None]
out = np.tanh(out * .9)
out *= 10 ** (-17 / 20) / np.sqrt(np.mean(out ** 2))
out = np.clip(out, -.8, .8)
with wave.open(sys.argv[2], "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR); w.writeframes((out * 32767).astype(np.int16).tobytes())
print(sys.argv[2], round(N / SR, 1), "s")
