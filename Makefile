IMAGE ?= lantern-sdn-ids
CASE ?= C5
CAMPAIGN ?=
DOCKER_READ = docker run --rm --network none -v "$(CURDIR):/opt/lantern" --entrypoint python3 $(IMAGE)
DOCKER_NET = docker run --rm --privileged --network none -v "$(CURDIR):/opt/lantern" $(IMAGE)

.PHONY: build test validate datapath-check integration plan pilot calibrate evaluate campaign analyze verify package clean clean-campaign run-case
build:
	docker build -f docker/Dockerfile -t $(IMAGE) .
test:
	$(DOCKER_READ) -m pytest tests/ -q -p no:cacheprovider
validate: test
	bash -n scripts/run_sweep.sh docker/entrypoint.sh
	docker run --rm --network none -v "$(CURDIR):/opt/lantern:ro" --entrypoint python3 $(IMAGE) -m experiments.run_all --trials 5 > /dev/null
datapath-check:
	$(DOCKER_NET) python3 -m topo.lantern_topo --self-test
integration:
	$(DOCKER_NET) python3 -m experiments.integration
plan:
	python3 -m experiments.run_all
campaign:
	@test -n "$(CAMPAIGN)" || (echo 'Set CAMPAIGN=results/campaigns/unique-name'; exit 1)
	python3 -m experiments.campaign all --campaign "$(CAMPAIGN)"
pilot calibrate evaluate:
	@test -n "$(CAMPAIGN)" || (echo 'Set CAMPAIGN=results/campaigns/unique-name'; exit 1)
	python3 -m experiments.campaign $(if $(filter calibrate,$@),calibrate,$@) --campaign "$(CAMPAIGN)"
analyze:
	@test -n "$(CAMPAIGN)" || (echo 'Set CAMPAIGN'; exit 1)
	$(DOCKER_READ) -m experiments.analyze --raw "$(CAMPAIGN)" --output "$(CAMPAIGN)/tables"
verify:
	$(DOCKER_READ) -m experiments.package verify
package:
	$(DOCKER_READ) -m experiments.package archive
run-case:
	$(DOCKER_NET) python3 -m experiments.run_case --case $(CASE)
clean:
	python3 -c "import pathlib,shutil; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__') if '.git' not in p.parts]; shutil.rmtree('.pytest_cache',ignore_errors=True)"
clean-campaign:
	@test -n "$(CAMPAIGN)" || (echo 'Set an explicit disposable CAMPAIGN path'; exit 1)
	python3 -c "from pathlib import Path; import shutil; p=Path('$(CAMPAIGN)').resolve(); root=Path('results/campaigns').resolve(); assert root in p.parents, 'Only results/campaigns children may be deleted'; shutil.rmtree(p)"
