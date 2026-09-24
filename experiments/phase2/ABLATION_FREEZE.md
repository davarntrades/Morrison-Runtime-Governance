# Excluded privileged-route control, pre-run

Source frozen at `2d23201978a0d167e79d6313daf20031a0f53f9a`, tree `8c724e2f608064b775ba752e4b305021e7556a7b`. Script SHA-256 `9f44621384c0d75cf71771975e5112c6887ad993fdc8247b6f5131d7a1e2d01f`; workflow SHA-256 `1bf6382137d2267c33fde1b7b96752801606054e06be60c829131e285386b067`. Production Morrison, verifier and CMA sources are unchanged.

This is deliberately **outside the scored governed endpoint**. A privileged harness uses the test-only `/ablation` credential once, then uses same-host OS filesystem access to change the SQLite resource file directly. The CMA model receives neither credential nor file access. This verifies the enumerated mediation surfaces and R6 sensitivity to an unlogged file mutation; it must never be counted among `/mutate` authority failures or live Worker successes.
