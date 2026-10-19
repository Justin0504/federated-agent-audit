# Build the paper.  Requires `tectonic` (which runs BibTeX automatically).
#   make            → main.pdf (camera-ready, with author)
#   make anon       → main_anon.pdf (double-blind: author hidden)
#   make arxiv      → arxiv_submission.zip, self-contained
#   make clean

main.pdf: main.tex paired_protocol.tex paired_protocol_results.tex final_native_results.tex final_native_appendix.tex core_narrative.tex core_case_figure.tex core_outcome_figure.tex appendix_cost_figure.tex appendix_audit_details.tex appendix_release_details.tex appendix_development.tex appendix_detector_studies.tex methodology.tex agentdojo_external.tex historical_measurements.tex references.bib $(wildcard ../figures/jetstream20261013/*) $(wildcard ../figures/agentdojo20261013/*.pdf)
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
arxiv: main.tex paired_protocol.tex paired_protocol_results.tex final_native_results.tex final_native_appendix.tex core_narrative.tex core_case_figure.tex core_outcome_figure.tex appendix_cost_figure.tex appendix_audit_details.tex appendix_release_details.tex appendix_development.tex appendix_detector_studies.tex methodology.tex agentdojo_external.tex historical_measurements.tex references.bib
	tectonic main.tex --keep-intermediates --keep-logs
	rm -rf .arxiv arxiv_submission.zip
	mkdir -p .arxiv/figures/icons/pdf .arxiv/figures/brands .arxiv/figures/semantic_icons
	cp main.tex paired_protocol.tex paired_protocol_results.tex final_native_results.tex final_native_appendix.tex core_narrative.tex core_case_figure.tex core_outcome_figure.tex appendix_cost_figure.tex appendix_audit_details.tex appendix_release_details.tex appendix_development.tex appendix_detector_studies.tex methodology.tex agentdojo_external.tex historical_measurements.tex references.bib main.bbl .arxiv/
	# the leading-underscore files are the local preview harness, not the paper
	for f in ../figures/*.tex; do case $$(basename $$f) in _*) ;; *) cp $$f .arxiv/figures/;; esac; done
	cp ../figures/icons/pdf/*.pdf .arxiv/figures/icons/pdf/
	cp ../figures/semantic_icons/*.pdf ../figures/semantic_icons/README.txt .arxiv/figures/semantic_icons/
	cp ../figures/brands/*.pdf ../figures/brands/LICENSE ../figures/brands/README.txt ../figures/brands/sources.json .arxiv/figures/brands/
	mkdir -p .arxiv/figures/jetstream20261013
	cp ../figures/jetstream20261013/*.pdf ../figures/jetstream20261013/appendix.tex .arxiv/figures/jetstream20261013/
	mkdir -p .arxiv/figures/agentdojo20261013
	cp ../figures/agentdojo20261013/*.pdf .arxiv/figures/agentdojo20261013/
	mkdir -p .arxiv/figures/final_native
	cp ../figures/final_native/*.pdf .arxiv/figures/final_native/
	mkdir -p .arxiv/figures/institution
	cp ../figures/institution/* .arxiv/figures/institution/
	cd .arxiv && tectonic main.tex >/dev/null
	cd .arxiv && rm -f main.pdf && zip -qr ../arxiv_submission.zip .
	rm -rf .arxiv
	@echo "→ arxiv_submission.zip ready to upload ($$(unzip -l arxiv_submission.zip | tail -1 | awk '{print $$2}') files)"

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.synctex.gz main_anon.tex arxiv_submission.zip
	rm -rf .arxiv
