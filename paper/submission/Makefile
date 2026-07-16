# Build the paper.  Requires `tectonic` (which runs BibTeX automatically).
#   make            → main.pdf (camera-ready, with author)
#   make anon       → main_anon.pdf (double-blind: author hidden)
#   make arxiv      → arxiv_submission.zip (main.tex + references.bib + main.bbl)
#   make clean

main.pdf: main.tex references.bib
	tectonic main.tex

.PHONY: anon arxiv clean
anon: main.tex references.bib
	sed 's/\\anonfalse/\\anontrue/' main.tex > main_anon.tex
	tectonic main_anon.tex

arxiv: main.tex references.bib
	tectonic main.tex --keep-intermediates
	rm -f arxiv_submission.zip
	zip arxiv_submission.zip main.tex references.bib main.bbl
	@echo "→ arxiv_submission.zip ready to upload"

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.synctex.gz main_anon.tex arxiv_submission.zip
