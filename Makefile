check_config_json:
	@if [ ! -f config.json ]; then \
		echo "config.json not found! Please consult the README for the structure of config.json"; \
		exit 1; \
	fi

build:
	mkdir -p results
	sudo python3 setup_cluster.py

confirm_action:
	@read -p "This will clear the results folder. Continue? (y/n) " ans; \
	if [ "$$ans" != "y" ]; then \
		echo "Action aborted."; \
		exit 1; \
	fi

clean: confirm_action
	sudo mn -c
	sudo rm -rf results/*
	mkdir -p results

all: check_config_json build