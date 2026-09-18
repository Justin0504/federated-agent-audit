# Build the paper.  Requires `tectonic` (which runs BibTeX automatically).
#   make            → main.pdf (camera-ready, with author)
#   make anon       → main_anon.pdf (double-blind: author hidden)
#   make arxiv      → arxiv_submission.zip, self-contained
#   make clean

main.pdf: main.tex references.bib
	tectonic main.tex

.PHONY: anon arxiv clean
anon: main.tex references.bib
	sed 's/\\anonfalse/\\anontrue/' main.tex > main_anon.tex
	tectonic main_anon.tex

# The figures live outside this directory (shared by all four builds via the
# `figures` symlink), so the upload has to carry real copies of them -- a zip of
# main.tex alone compiles here and fails on arXiv. Staged into a temp tree and
# test-compiled from there, so a missing dependency fails the build instead of
# being discovered by arXiv.
arxiv: main.tex references.bib
	tectonic main.tex --keep-intermediates
	rm -rf .arxiv arxiv_submission.zip
	mkdir -p .arxiv/figures/icons/pdf
	cp main.tex references.bib main.bbl .arxiv/
	# the leading-underscore files are the local preview harness, not the paper
	for f in ../figures/*.tex; do case $$(basename $$f) in _*) ;; *) cp $$f .arxiv/figures/;; esac; done
	cp ../figures/icons/pdf/*.pdf .arxiv/figures/icons/pdf/
	cd .arxiv && tectonic main.tex >/dev/null
	cd .arxiv && rm -f main.pdf && zip -qr ../arxiv_submission.zip .
	rm -rf .arxiv
	@echo "→ arxiv_submission.zip ready to upload ($$(unzip -l arxiv_submission.zip | tail -1 | awk '{print $$2}') files)"

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.synctex.gz main_anon.tex arxiv_submission.zip
	rm -rf .arxiv
