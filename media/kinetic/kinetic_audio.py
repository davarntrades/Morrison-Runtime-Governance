"""Beat + hits for paper.html, built from the page's cues (120 bpm, cuts on the beat).

    python3 kinetic_audio.py cues.json out.wav
"""
import json, sys, wave
import numpy as np
from scipy.signal import butter, sosfilt

SR = 48000
rng = np.random.default_rng(7)
spec = json.load(open(sys.argv[1]))
TOTAL, CUES = spec["total"], spec["cues"]
N = int(SR * (TOTAL + .5))
out = np.zeros((N, 2))
T = lambda d: np.arange(int(SR * d)) / SR
lp = lambda s, f: sosfilt(butter(2, f, "low", fs=SR, output="sos"), s)
hp = lambda s, f: sosfilt(butter(2, f, "high", fs=SR, output="sos"), s)
bp = lambda s, a, b: sosfilt(butter(2, [a, b], "band", fs=SR, output="sos"), s)


def put(sig, t0, g=1.0, pan=0.0):
    i = int(SR * t0); j = min(N, i + len(sig))
    if 0 <= i < N:
        out[i:j, 0] += g * sig[: j - i] * (1 - pan) ** .5
        out[i:j, 1] += g * sig[: j - i] * (1 + pan) ** .5


def kick(d=.35):
    t = T(d); return np.tanh(2.2 * np.sin(2 * np.pi * np.cumsum(45 + 120 * np.exp(-t * 28)) / SR) * np.exp(-t * 7))


def rustle(d=.16):  # paper snap on each cut
    t = T(d); return bp(rng.standard_normal(len(t)), 1500, 9000) * np.exp(-t * 30) * (1 + .6 * np.sin(2 * np.pi * 60 * t))


def hat():
    t = T(.04); return hp(rng.standard_normal(len(t)), 8000) * np.exp(-t * 110)


def whoosh(d, rise=True):
    t = T(d); k = t / d if rise else 1 - t / d; n = rng.standard_normal(len(t))
    return (lp(n, 1200) * (1 - k) + hp(n, 3000) * k) * (k ** 2 if rise else np.sin(np.pi * k)) * .6


def key():
    t = T(.03); return hp(rng.standard_normal(len(t)), 2500) * np.exp(-t * 220)


cut = [t for t, k in CUES if k == "cut"]
sub = [t for t, k in CUES if k == "sub"]
drop = next(t for t, k in CUES if k == "drop")
# bed: sub on every beat until the drop, offbeat hats, a minor stab per bar
beat = .5
for b in range(int(drop / beat) + 1):
    t0 = .7 + b * beat
    if t0 >= drop: break
    put(hat(), t0 + beat / 2, .35, pan=.3)
    if b % 4 == 0:
        t = T(beat * 4); f = [55.0, 43.65, 49.0, 41.2][(b // 4) % 4]
        put(np.sin(2 * np.pi * f * t) * np.exp(-t * .9) * np.minimum(1, t / .01), t0, .5)
        st = T(.5); put(lp(sum(np.sign(np.sin(2 * np.pi * f * 4 * m * st)) for m in (1, 1.189, 1.498)), 1400) * np.exp(-st * 6) * .25, t0, .35, pan=-.2)
for t0 in cut:
    put(kick(), t0, .9); put(rustle(), t0, .5, pan=rng.uniform(-.4, .4))
for t0 in sub:  # the in-burst changes: a lighter paper flick, no kick
    put(rustle(.08), t0, .28, pan=rng.uniform(-.5, .5))
put(whoosh(.7), 0, .6)
put(whoosh(.5), drop - .5, .7)
put(kick(.8) * 1.3, drop, 1.0)
for t0, k in CUES:
    if k == "key": put(key(), t0, .35, pan=rng.uniform(-.2, .2))
    if k == "end":
        t = T(1.6); put(sum(np.sin(2 * np.pi * f * t) for f in (220.0, 261.6, 329.6, 440.0)) * np.exp(-t * 1.8) * .22, t0, .7)

out *= np.interp(np.arange(N) / SR, [0, .05, TOTAL - .4, TOTAL], [0, 1, 1, 0])[:, None]
out = np.tanh(out * .9)
out *= 10 ** (-17 / 20) / np.sqrt(np.mean(out ** 2))
out = np.clip(out, -.75, .75)
with wave.open(sys.argv[2], "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR); w.writeframes((out * 32767).astype(np.int16).tobytes())
print(sys.argv[2], round(N / SR, 1), "s")
