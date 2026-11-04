#ifndef RUNNER_SECURE_STORE_PLUGIN_H_
#define RUNNER_SECURE_STORE_PLUGIN_H_

#include <flutter/binary_messenger.h>

// Registers `com.omnifi/secure_store` -- `read` / `write` / `delete` -- on
// |messenger|, backed by the Windows Credential Manager.
//
// The handler outlives this call: `SetMethodCallHandler` hands ownership of
// the callback to the messenger, so it keeps answering for as long as the
// engine does.
void RegisterSecureStorePlugin(flutter::BinaryMessenger* messenger);

#endif  // RUNNER_SECURE_STORE_PLUGIN_H_
