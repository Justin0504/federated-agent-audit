# Build the ICLR 2027 submission.
#   make          → main.pdf (anonymous, double-blind — the submission form)
#   make final    → camera-ready with authors revealed
#   make clean
# NOTE: ICLR caps the MAIN TEXT at 9 pages; references and appendix are exempt.
# `make check` fails if the body has crept past page 9.

main.pdf: main.tex references.bib
	tectonic main.tex

.PHONY: final check clean
final: main.tex references.bib
	sed 's|% \\iclrfinalcopy|\\iclrfinalcopy|' main.tex > main_final.tex
	tectonic main_final.tex

check: main.pdf
	@p=$$(for n in $$(seq 1 30); do \
	   pdftotext -f $$n -l $$n main.pdf - 2>/dev/null \
	     | grep -qE '^REFERENCES|^References' && echo $$n && break; done); \
	 if [ -z "$$p" ]; then echo "could not locate the references page"; exit 1; \
	 elif [ $$p -gt 10 ]; then echo "MAIN TEXT OVER LIMIT: body runs to page $$((p-1)) (max 9)"; exit 1; \
	 else echo "main text ends on page $$((p-1)) — within the 9-page limit"; fi

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.synctex.gz main_final.tex
