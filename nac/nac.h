#include <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <time.h>
#include <stdlib.h>
#include <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>

// Legacy function pointer approach for older macOS versions
int nacInitProxy(void *addr, const void *cert_bytes, int cert_len, void **out_validation_ctx, void **out_request_bytes, int *out_request_len);
int nacKeyEstablishmentProxy(void *addr, void *validation_ctx, void *response_bytes, int response_len);
int nacSignProxy(void *addr, void *validation_ctx, void *unk_bytes, int unk_len, void **validation_data, int *validation_data_len);

// New Objective-C method approach for macOS Sequoia (15.6+)
int nacSequoiaInitProxy(void *cert_bytes, int cert_len, void **out_validation_ctx, void **out_request_bytes, int *out_request_len);
int nacSequoiaKeyEstablishmentProxy(void *validation_ctx, void *response_bytes, int response_len);
int nacSequoiaSignProxy(void *validation_ctx, void *unk_bytes, int unk_len, void **validation_data, int *validation_data_len);

// Sequoia sanity check that tests the methods are accessible
int nacSequoiaSanityCheck();

NSAutoreleasePool* meowMakePool();
void meowReleasePool(NSAutoreleasePool* pool);
