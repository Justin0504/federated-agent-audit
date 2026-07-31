# Build the PoPETs 2027 submission (acmart + popets.sty, double-blind).
#   make          → main.pdf (anonymous, review mode with line numbers)
#   make view     → build + open the PDF
#   make clean
# Requires `tectonic` (runs BibTeX automatically). The popets.sty / acmart.cls /
# ACM-Reference-Format.bst here are the official PoPETs 2027 template files and
# must not be modified.

main.pdf: main.tex references.bib popets.sty acmart.cls
	tectonic main.tex

.PHONY: view clean
view: main.pdf
	open main.pdf

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.xdv *.synctex.gz
