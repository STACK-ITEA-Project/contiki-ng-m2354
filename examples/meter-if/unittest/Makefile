MODULE_PATH=../

Q=@
CC=gcc

UNITTEST_INCS += -I.
CFLAGS += $(UNITTEST_INCS)
CFLAGS += -DDS_UNITTEST

UNITTEST_SRCS=meterif_data.c adc_data.c
UNITTEST_OBJS=$(UNITTEST_SRCS:.c=.o)
UNITTEST_APPS=$(basename $(notdir $(UNITTEST_SRCS)))
UNITTEST_DEP=$(notdir $(UNITTEST_SRCS:.c=.d))
#UNITTEST_DEP=$(addprefix dep/,$(notdir $(UNITTEST_SRCS:.c=.d)))
UNITTEST_GCDAS=$(notdir $(UNITTEST_SRCS:.c=.gcda))
UNITTEST_GCNOS=$(notdir $(UNITTEST_SRCS:.c=.gcno))
CFLAGS += --coverage -g
LDFLAGS += --coverage

all: $(UNITTEST_APPS) test cov

$(UNITTEST_APPS):%: %.o
	$(Q)$(CC) $(LDFLAGS) -o $@ $?

%.o: %.c %.d
	$(Q)$(CC) -c $(CFLAGS) -o $@ $<

.PNONY: test

test: $(UNITTEST_APPS)
	$(foreach app,$(UNITTEST_APPS),  \
                echo $(app) \
		$(shell ./$(app)) \
	 )

cov: test
	@gcov $(UNITTEST_GCDAS) $(UNITTEST_GCNOS)
	@lcov -q -c -b . -d . -o coverage.info
	@genhtml coverage.info -o coverage | grep "%"

clean:
	@rm -rf $(UNITTEST_APPS) *.o *.d *.gcno *.gcda *.gcov *.info coverage

%.d:$(MODULE_PATH)/%.c
	@$(CC) $(CFLAGS) -MM -o $@ $<
-include $(UNITTEST_DEP)
