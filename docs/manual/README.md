# Voider customer manual

German, English and Bulgarian review editions, updated for the USB workflow
rewrite on 2026-09-21. These are **not a customer release approval**. Physical
USB acceptance, hardware handoff and the remaining release gates are separate.
No hardware specifications, package contents, phone keys or support contacts
have been invented.

## Build and review

Dependencies on Debian/Ubuntu: `texlive-latex-base`, `texlive-latex-recommended`,
`texlive-latex-extra`, `texlive-pictures`, `texlive-lang-german`,
`texlive-lang-cyrillic`, `cm-super-minimal`, `poppler-utils`, `python3` and
`python3-pil`. A full CM-Super installation also includes the minimal maps.
Use pdfLaTeX, not XeLaTeX or LuaLaTeX. Bulgarian uses UTF-8 input, T2A encoding,
Babel's Bulgarian patterns and embedded CM-Super Type 1 fonts. The UI images
retain the application's DINish font and Bulgarian forms; see
[`assets/fonts/OFL.txt`](../../assets/fonts/OFL.txt).

From the repository root:

```sh
./docs/manual/build.sh
python3 docs/manual/review.py
(cd release && sha256sum -c voider-manual.sha256)
```

`build.sh` runs pdfLaTeX three times per edition, checks label drift and failed
references/overfull boxes/missing glyphs, and copies only PDFs into `release/`.
Auxiliary files and proofs stay in ignored `docs/manual/.build/`.
`review.py` checks page counts against the source sections, A5 size, embedded
Unicode fonts, text bounds and Cyrillic extraction, then renders **every page**
at 110 dpi and makes four-page proof sheets. Inspect the individual PNGs as well
as sheets when changing layout; automated checks do not establish readability.

Actual final compilation:

| PDF under `release/` | Pages | Language start pages |
| --- | ---: | --- |
| `voider-manual-de.pdf` | 14 | German 1 |
| `voider-manual-en.pdf` | 14 | English 1 |
| `voider-manual-bg.pdf` | 14 | Bulgarian 1 |
| `voider-manual-de-en-bg.pdf` | 43 | German 2, English 16, Bulgarian 30 |

The PDFs are A5, 148 × 210 mm, in reading order with clickable references and
language/chapter bookmarks. Body text is 12 pt; captions and release notes are
10 pt; footers are 9–10 pt. No blank padding or reduced body text was used to
reach a page count. For a folded booklet, let the printer impose the pages and
add any blank sheets it needs; these files are not printer spreads.

The build host lacked language packages. For this run, the Ubuntu packages
`texlive-lang-cyrillic=2023.20240207-1`,
`texlive-lang-german=2023.20240207-1` and `cm-super-minimal=0.3.4-17` were
downloaded and extracted under `/tmp/voider-manual-tex/root`, without system
installation. A local pdfLaTeX format loaded both hyphenation tables. The exact
build environment used was:

```sh
TEXMFHOME='{/tmp/voider-manual-tex/root/usr/share/texlive/texmf-dist,/tmp/voider-manual-tex/root/usr/share/texmf}' \
TEXFORMATS='/tmp/voider-manual-tex:' ./docs/manual/build.sh
```

That temporary workaround is not needed with the normal dependencies installed.
For a fresh sandbox, extract the three `.deb` files with `dpkg-deb -x`, copy the
system `language.dat` to a temporary config directory, append
`bulgarian loadhyph-bg.tex` and `ngerman loadhyph-de-1996.tex` if absent, then run
`pdftex -ini -etex -jobname=pdflatex -progname=pdflatex pdflatex.ini` in the
temporary format directory with that directory's config on `TEXINPUTS` and the
same `TEXMFHOME`. Point `TEXFORMATS` at the resulting format as above.

## Maintain one set of instructions

`manual.tex` owns typography, diagrams, navigation and edition selection.
`de.tex`, `en.tex`, `bg.tex` have the same 14 named sections and procedures.
All editions include those same files; there are no separate combined-PDF
translations. `ui-labels.tex` is generated from the application's TSV. `\UI{KEY}`
prints the exact translated label without breaking it across lines.

For a single edition, the underlying command is:

```sh
cd docs/manual
mkdir -p .build
pdflatex -halt-on-error -interaction=nonstopmode -output-directory=.build \
  -jobname=voider-manual-bg '\def\ManualLanguage{bg}\input{manual.tex}'
# Repeat until references settle (the build script runs three passes).
```

After a UI change, review the procedure first, then run
`python3 docs/manual/labels.py`. The build rejects a stale label snapshot or
different section order. It does not assert semantic translation quality.

Screenshots are unedited 320×240 **actual C++ renderer output with synthetic
fixtures**, not photos or captures of the paired appliances. Their captions
identify examples. No customer/device fingerprint is embedded. To regenerate:

```sh
make build/voider-ui
./build/voider-ui --render-dir /tmp/voider-manual-ui
python3 - <<'PY'
from pathlib import Path
from PIL import Image
for lang in ('de', 'en', 'bg'):
    for page in ('language', 'factory-READY', 'integrity_state', 'contact'):
        source = Path('/tmp/voider-manual-ui') / lang / (page + '.ppm')
        dest = Path('docs/manual/assets') / lang / (page + '.png')
        Image.open(source).save(dest)
PY
```

This invokes only the host renderer. It does not dispatch physical buttons or
access an appliance. The candidate's installer gate is still pending; generating
these documentation fixtures does not declare the product/UI released.

## Procedure cross-check and remaining gates

The three language sources describe the same USB and management procedures:
SHARE and BACKUP require held whole-stick erasure; ADD and RESTORE validate
read-only. RESTORE requires a second confirmation, records the new check code,
then requires an explicit restart. Saves from old RAM are blocked until restart.
ADMIN offers contextual LOGIN KEY, SSH ON/OFF and permanent key removal. A failed
USB operation retains the existing login key and access setting.

Bundle formats and existing pairing identities remain compatible. Device
check codes are separate per-appliance STATE fingerprints, not a human pairing
fingerprint. Physical panel readability, native-language review and a beginner
following the physical workflow remain acceptance work.

Remaining customer release gates include final enclosure/socket labels, power
requirements and supported phone model/firmware/key sequence; human pairing
verification; factory SSH state/switch and host-key handoff; fresh physical
installations and key lifecycle tests; the reconnection matrix and full Tor
stability acceptance. Prior Tor observation was 601 seconds, not one hour.
See the existing README and ignored consolidated evidence for current software
validation. Historical rendered proofs do not validate this revision's layout.
