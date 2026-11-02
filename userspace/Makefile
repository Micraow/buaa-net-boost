BIN := bin

.PHONY: all clean
all: $(BIN)/tcp-race $(BIN)/udp-race $(BIN)/probe

$(BIN)/tcp-race: $(wildcard cmd/tcp-race/*.go internal/race/*.go go.mod)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/tcp-race

$(BIN)/udp-race: $(wildcard cmd/udp-race/*.go internal/race/*.go go.mod)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/udp-race

$(BIN)/probe: $(wildcard cmd/probe/*.go internal/race/*.go go.mod)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/probe

clean:
	rm -rf $(BIN)
