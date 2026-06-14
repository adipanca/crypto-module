CC = gcc
OPENSSL_CFLAGS = $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS = $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS = -lcrypto
endif

CFLAGS = -std=c11 -O2 -Wall -Wextra -Iinclude $(OPENSSL_CFLAGS)
LDFLAGS = $(OPENSSL_LIBS)

SRC = $(wildcard src/core/*.c src/primitives/*.c src/selftest/*.c src/integrity/*.c src/entropy/*.c src/platform/*.c)
OBJ = $(patsubst %.c,build/%.o,$(SRC))

TEST_MAIN = build/cryptomod_test
TEST_FSM = build/test_fsm
TEST_SELFTEST = build/test_selftest
TEST_KAT = build/test_kat
TEST_INTEGRITY = build/test_integrity
TEST_ENTROPY = build/test_entropy
TEST_NEGATIVE = build/test_negative
TEST_MLKEM = build/test_mlkem
TEST_ASSESSMENT = build/test_assessment
TEST_BENCH = build/test_benchmark

ALL_BINS = $(TEST_MAIN) $(TEST_FSM) $(TEST_SELFTEST) $(TEST_KAT) $(TEST_INTEGRITY) $(TEST_ENTROPY) $(TEST_NEGATIVE) $(TEST_MLKEM) $(TEST_ASSESSMENT) $(TEST_BENCH)
ALL_HASH = $(ALL_BINS:%=%.sha256)

all: $(ALL_BINS) $(ALL_HASH)

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_MAIN): $(OBJ) build/tests/test_runner.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_FSM): $(OBJ) build/tests/test_fsm.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_SELFTEST): $(OBJ) build/tests/test_selftest.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_KAT): $(OBJ) build/tests/test_kat.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_INTEGRITY): $(OBJ) build/tests/test_integrity.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_ENTROPY): $(OBJ) build/tests/test_entropy.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_NEGATIVE): $(OBJ) build/tests/test_negative.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_MLKEM): $(OBJ) build/tests/test_mlkem.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_ASSESSMENT): $(OBJ) build/tests/test_assessment.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_BENCH): $(OBJ) build/tests/test_benchmark.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.sha256: %
	@shasum -a 256 "$<" | awk '{print $$1}' > "$@"

test: all
	./$(TEST_MAIN)

test-fsm: all
	./$(TEST_FSM)

test-selftest: all
	./$(TEST_SELFTEST)

test-kat: all
	./$(TEST_KAT)

test-integrity: all
	./$(TEST_INTEGRITY)

test-entropy: all
	./$(TEST_ENTROPY)

test-negative: all
	./$(TEST_NEGATIVE)

test-mlkem: all
	./$(TEST_MLKEM)

test-assessment: all
	./$(TEST_ASSESSMENT)

test-bench: all
	./$(TEST_BENCH)

test-all: test test-fsm test-selftest test-kat test-integrity test-entropy test-negative test-mlkem test-assessment

define COV_TEMPLATE
coverage-$(1):
	@$(MAKE) clean >/dev/null
	@$(MAKE) CFLAGS='$(CFLAGS) --coverage -O0' LDFLAGS='$(LDFLAGS) --coverage' $(2) $(2).sha256 >/dev/null
	@./$(2) >/dev/null
	@mkdir -p coverage
	@gcov -b -c -o build $(SRC) > coverage/$(1).txt 2>/dev/null || true
	@echo "Coverage report generated: coverage/$(1).txt"
	@$(MAKE) clean >/dev/null
endef

$(eval $(call COV_TEMPLATE,main,$(TEST_MAIN)))
$(eval $(call COV_TEMPLATE,fsm,$(TEST_FSM)))
$(eval $(call COV_TEMPLATE,selftest,$(TEST_SELFTEST)))
$(eval $(call COV_TEMPLATE,kat,$(TEST_KAT)))
$(eval $(call COV_TEMPLATE,integrity,$(TEST_INTEGRITY)))
$(eval $(call COV_TEMPLATE,entropy,$(TEST_ENTROPY)))
$(eval $(call COV_TEMPLATE,negative,$(TEST_NEGATIVE)))
$(eval $(call COV_TEMPLATE,mlkem,$(TEST_MLKEM)))
$(eval $(call COV_TEMPLATE,assessment,$(TEST_ASSESSMENT)))

coverage-all: coverage-main coverage-fsm coverage-selftest coverage-kat coverage-integrity coverage-entropy coverage-negative coverage-mlkem coverage-assessment

clean:
	rm -rf build

.PHONY: all clean test test-fsm test-selftest test-kat test-integrity test-entropy test-negative test-mlkem test-assessment test-bench test-all coverage-main coverage-fsm coverage-selftest coverage-kat coverage-integrity coverage-entropy coverage-negative coverage-mlkem coverage-assessment coverage-all
