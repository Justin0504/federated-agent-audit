# Build the IEEE S&P 2027 submission (IEEEtran compsoc conference, double-blind).
#   make        -> main.pdf
#   make clean
# Requires `tectonic` (fetches IEEEtran.cls + IEEEtran.bst from CTAN automatically;
# nothing to vendor). US letter, 13pp body + 5pp refs. Do not alter margins/fonts.

main.pdf: main.tex references.bib
	tectonic main.tex

.PHONY: clean
clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.xdv *.synctex.gz
