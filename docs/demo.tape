# Teaser for tiyaverma.us — render with:  vhs docs/demo.tape   (from repo root)
#
# Replays a RECORDED benchmark run (no API key, no live model call), so the
# output is real and identical every render. Re-record after each new
# benchmark run by pointing RUN at the new results file and re-checking that
# the end-card numbers match benchmark/README.md.

Output docs/demo.gif
Output docs/demo.mp4

Set Shell zsh
Set FontSize 20
Set Width 1280
Set Height 560
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms

Hide
# zsh needs interactivecomments for the `#` caption lines to be comments.
Type "setopt interactivecomments; export VIRTUAL_ENV_DISABLE_PROMPT=1; source .venv/bin/activate" Enter
Type "PS1='%F{magenta}$%f '" Enter
Type "export COLUMNS=96 RUN=benchmark/results/results-v0.1.0-diff-20261117T121706.json" Enter
Type "PR=benchmark/corpus/samples/cve_2024_22195_jinja_xmlattr_injection_positive.diff" Enter
Type "clear" Enter
Show

# Beat 1 — the code under review: real pre-fix Jinja2 (CVE-2024-22195)
Type "# A real PR: the Jinja2 xmlattr filter, before the CVE-2024-22195 fix" Enter
Sleep 600ms
Type "sed -n '24,28p' $PR" Enter
Sleep 2.5s

# Beat 2 — generator alone: catches the bug, plus noise
Type "clear" Enter
Type "# Generator alone: high recall, but noisy" Enter
Type "secreview replay $RUN cve-2024-22195-jinja-positive --no-verifier" Enter
Sleep 4s

# Beat 3 — verifier tries to prove each finding safe; the real one survives
Type "clear" Enter
Type "# + Verifier: tries to prove every finding is a false positive" Enter
Type "secreview replay $RUN cve-2024-22195-jinja-positive --show-rejected" Enter
Sleep 5s

# Beat 4 — end card (numbers from benchmark/README.md, same results file)
Hide
Type "clear; printf '\n  false positives   28 -> 8\n  precision         0.33 -> 0.62\n  recall            0.93 -> 0.87\n\n  24 labeled samples, 3 languages, one run\n  sonnet-5 generator, opus-4.8 verifier\n'" Enter
Show
Sleep 5s
