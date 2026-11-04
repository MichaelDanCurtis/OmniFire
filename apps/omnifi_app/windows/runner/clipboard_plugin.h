#ifndef RUNNER_CLIPBOARD_PLUGIN_H_
#define RUNNER_CLIPBOARD_PLUGIN_H_

#include <windows.h>

#include <flutter/binary_messenger.h>

// Registers `com.omnifi/clipboard` (`write` / `start` / `stop`) and the
// `com.omnifi/clipboard/changes` event channel on |messenger|.
//
// |window| is the top-level window that will receive WM_CLIPBOARDUPDATE and
// that owns the clipboard while we write to it. The clipboard format listener
// is not registered here but in `start`, so that a registration failure
// surfaces to Dart as a failed `start` rather than as an app that runs
// happily and never sees a copy.
void RegisterClipboardPlugin(flutter::BinaryMessenger* messenger, HWND window);

// Drops the format listener and the event sink. Call from the window's
// OnDestroy, before the engine is torn down: a WM_CLIPBOARDUPDATE that arrives
// mid-teardown would otherwise push an event into a messenger that is on its
// way out.
void UnregisterClipboardPlugin();

// Call from the window procedure for WM_CLIPBOARDUPDATE.
void OnClipboardUpdate();

#endif  // RUNNER_CLIPBOARD_PLUGIN_H_
