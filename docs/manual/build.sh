#!/bin/sh
# Run from any directory. No appliance access and no application changes.
set -eu
cd "$(dirname "$0")"
mkdir -p ../../release .build
python3 labels.py --check
for lang in de en bg all; do
    name="voider-manual-$lang"
    [ "$lang" != all ] || name=voider-manual-de-en-bg
    pass=1
    while [ "$pass" -le 3 ]; do
        pdflatex -halt-on-error -interaction=nonstopmode -file-line-error \
            -output-directory=.build -jobname="$name" \
            "\def\ManualLanguage{$lang}\input{manual.tex}" >".build/$name.build.log" 2>&1 || {
                cat ".build/$name.build.log"; exit 1;
            }
        pass=$((pass + 1))
    done
    if grep -E 'Overfull|Missing character|undefined references|Rerun to get' ".build/$name.log"; then
        echo "Layout/reference check failed: $name" >&2; exit 1
    fi
    cp ".build/$name.pdf" "../../release/$name.pdf"
    pdfinfo "../../release/$name.pdf" | grep -E 'Pages:|Page size:'
done
(cd ../../release && sha256sum voider-manual-de.pdf voider-manual-en.pdf \
    voider-manual-bg.pdf voider-manual-de-en-bg.pdf > voider-manual.sha256)
