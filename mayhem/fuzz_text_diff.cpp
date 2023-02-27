#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int *text_diff(char *a, char *b);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char *a = strdup(provider.ConsumeRandomLengthString(1000).c_str());
    char *b = strdup(provider.ConsumeRandomLengthString(1000).c_str());

    text_diff(a, b);

    free(a);
    free(b);
    return 0;
}
