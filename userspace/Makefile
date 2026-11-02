BIN := bin

.PHONY: all clean
all: $(BIN)/tcp-race $(BIN)/udp-race $(BIN)/probe $(BIN)/spray-helper

$(BIN)/tcp-race: $(wildcard cmd/tcp-race/*.go internal/race/*.go go.mod)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/tcp-race

$(BIN)/udp-race: $(wildcard cmd/udp-race/*.go internal/race/*.go go.mod)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/udp-race

$(BIN)/probe: $(wildcard cmd/probe/*.go internal/race/*.go go.mod)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/probe

$(BIN)/spray-helper: $(wildcard cmd/spray-helper/*.go go.mod)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/spray-helper

clean:
	rm -rf $(BIN)
