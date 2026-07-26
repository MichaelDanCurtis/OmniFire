#include "clipboard_plugin.h"

#include <windows.h>

#include <flutter/encodable_value.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace {

using flutter::EncodableMap;
using flutter::EncodableValue;

std::unique_ptr<flutter::EventSink<EncodableValue>> g_sink;
std::unique_ptr<flutter::MethodChannel<EncodableValue>> g_methods;
std::unique_ptr<flutter::EventChannel<EncodableValue>> g_events;

HWND g_window = nullptr;

// Whether AddClipboardFormatListener has succeeded for `g_window`.
bool g_listening = false;

// Whether Dart has called `start` and not yet `stop`. Windows keeps posting
// WM_CLIPBOARDUPDATE for as long as the listener is registered, so this is
// what gives `stop` the same meaning it has on macOS: after it, we no longer
// read the user's clipboard at all.
bool g_started = false;

// The clipboard sequence number produced by our own last write. See
// MarkSelfWrite.
DWORD g_self_write_sequence = 0;
bool g_self_write_valid = false;

// Attempts to open the clipboard. Another process (a clipboard manager, or the
// app that just copied) can hold it for a moment, and OpenClipboard simply
// fails while it does. Five tries at 10 ms is a worst case of 50 ms on the
// platform thread, which is a visible-but-tolerable hitch, against losing the
// event entirely.
constexpr int kOpenAttempts = 5;
constexpr DWORD kOpenRetryMs = 10;

// Opens the clipboard for the duration of a scope and closes it on every exit
// path. Leaving the clipboard open would lock every other process out of it.
class ClipboardLock {
 public:
  explicit ClipboardLock(HWND owner) {
    for (int attempt = 0; attempt < kOpenAttempts; ++attempt) {
      if (OpenClipboard(owner)) {
        held_ = true;
        return;
      }
      if (attempt + 1 < kOpenAttempts) {
        Sleep(kOpenRetryMs);
      }
    }
  }

  ~ClipboardLock() {
    if (held_) {
      CloseClipboard();
    }
  }

  ClipboardLock(const ClipboardLock&) = delete;
  ClipboardLock& operator=(const ClipboardLock&) = delete;

  bool held() const { return held_; }

 private:
  bool held_ = false;
};

// Password managers put this format on the clipboard to tell monitors -- which
// is exactly what this plugin is -- not to process the entry. Honouring it is
// the privacy default, not an option: without it, every password copied on
// this machine would be broadcast to every paired device.
//
// Registered lazily; RegisterClipboardFormatW returns 0 on failure, which
// `start` refuses to run past.
UINT ExcludeFormat() {
  static const UINT format =
      RegisterClipboardFormatW(L"ExcludeClipboardContentFromMonitorProcessing");
  return format;
}

// The de-facto registered name for raw PNG bytes on the Windows clipboard;
// browsers, Office and the common chat clients all read and write it.
UINT PngFormat() {
  static const UINT format = RegisterClipboardFormatW(L"PNG");
  return format;
}

// UTF-16 to UTF-8. An explicit source length (rather than -1) means the
// returned size excludes the terminator, so there is no off-by-one.
bool Narrow(const wchar_t* wide, size_t wide_length, std::string* out) {
  out->clear();
  if (wide_length == 0) {
    return true;
  }
  if (wide_length > static_cast<size_t>(INT_MAX)) {
    return false;
  }
  const int length = static_cast<int>(wide_length);
  const int size = WideCharToMultiByte(CP_UTF8, 0, wide, length, nullptr, 0,
                                       nullptr, nullptr);
  if (size <= 0) {
    return false;
  }
  out->resize(static_cast<size_t>(size));
  const int written = WideCharToMultiByte(CP_UTF8, 0, wide, length, out->data(),
                                          size, nullptr, nullptr);
  return written == size;
}

// UTF-8 to UTF-16. MB_ERR_INVALID_CHARS makes this a validation rather than a
// silent substitution of U+FFFD for malformed input.
bool Widen(const std::string& utf8, std::wstring* out) {
  out->clear();
  if (utf8.empty()) {
    return true;
  }
  if (utf8.size() > static_cast<size_t>(INT_MAX)) {
    return false;
  }
  const int length = static_cast<int>(utf8.size());
  const int wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                              utf8.data(), length, nullptr, 0);
  if (wide_length <= 0) {
    return false;
  }
  out->resize(static_cast<size_t>(wide_length));
  const int written =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), length,
                          out->data(), wide_length);
  return written == wide_length;
}

// Requires an open clipboard.
bool ReadClipboardText(std::string* out) {
  HANDLE handle = GetClipboardData(CF_UNICODETEXT);
  if (handle == nullptr) {
    return false;
  }
  const size_t bytes = GlobalSize(handle);
  auto* wide = static_cast<const wchar_t*>(GlobalLock(handle));
  if (wide == nullptr) {
    return false;
  }
  // Bounded by the allocation rather than trusting a terminator to be there.
  const size_t limit = bytes / sizeof(wchar_t);
  size_t length = 0;
  while (length < limit && wide[length] != L'\0') {
    ++length;
  }
  const bool ok = Narrow(wide, length, out);
  GlobalUnlock(handle);
  return ok;
}

// Requires an open clipboard.
bool ReadClipboardPng(std::vector<uint8_t>* out) {
  const UINT format = PngFormat();
  if (format == 0) {
    return false;
  }
  HANDLE handle = GetClipboardData(format);
  if (handle == nullptr) {
    return false;
  }
  const size_t bytes = GlobalSize(handle);
  if (bytes == 0) {
    return false;
  }
  auto* data = static_cast<const uint8_t*>(GlobalLock(handle));
  if (data == nullptr) {
    return false;
  }
  out->assign(data, data + bytes);
  GlobalUnlock(handle);
  return true;
}

// Records the clipboard state our own write produced, so that the
// WM_CLIPBOARDUPDATE it causes is not read back as a fresh local copy and
// bounced to the peer that sent it. This is the Windows counterpart of the
// macOS plugin claiming `NSPasteboard.changeCount` after a write.
//
// The sequence number is monotonic, so a match can only ever be our own write;
// the flag is cleared after one match. GetClipboardSequenceNumber returns 0
// when the process lacks WINSTA_ACCESSCLIPBOARD, hence the separate validity
// flag rather than treating 0 as a sentinel -- otherwise a 0 return would
// suppress *every* event. If this suppression misses, ClipboardSync's
// content-hash check in Dart still drops the echo; this only avoids the round
// trip.
void MarkSelfWrite() {
  const DWORD sequence = GetClipboardSequenceNumber();
  g_self_write_sequence = sequence;
  g_self_write_valid = sequence != 0;
}

// Puts |bytes| on the clipboard as |format|.
//
// Ownership is the trap here. If SetClipboardData succeeds the system owns the
// allocation and freeing it would be a double free; on every failure path we
// still own it and must free it ourselves.
bool SetClipboardBlob(UINT format,
                      const void* bytes,
                      size_t size,
                      DWORD* error) {
  if (size == 0) {
    *error = ERROR_INVALID_PARAMETER;
    return false;
  }
  HGLOBAL global = GlobalAlloc(GMEM_MOVEABLE, size);
  if (global == nullptr) {
    *error = GetLastError();
    return false;
  }
  void* dest = GlobalLock(global);
  if (dest == nullptr) {
    *error = GetLastError();
    GlobalFree(global);
    return false;
  }
  std::memcpy(dest, bytes, size);
  GlobalUnlock(global);

  {
    ClipboardLock lock(g_window);
    if (!lock.held()) {
      *error = GetLastError();
      GlobalFree(global);
      return false;
    }
    if (!EmptyClipboard()) {
      *error = GetLastError();
      GlobalFree(global);
      return false;
    }
    if (SetClipboardData(format, global) == nullptr) {
      *error = GetLastError();
      GlobalFree(global);
      return false;
    }
    // From here on the system owns `global`.
  }

  // After CloseClipboard, so the sequence number read is the one the pending
  // WM_CLIPBOARDUPDATE will be delivered against.
  MarkSelfWrite();
  return true;
}

std::string SystemErrorMessage(DWORD error) {
  LPWSTR buffer = nullptr;
  const DWORD chars = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
  std::string text;
  if (chars != 0 && buffer != nullptr) {
    size_t length = chars;
    while (length != 0 &&
           (buffer[length - 1] == L'\n' || buffer[length - 1] == L'\r')) {
      --length;
    }
    Narrow(buffer, length, &text);
  }
  if (buffer != nullptr) {
    LocalFree(buffer);
  }
  if (text.empty()) {
    text = "no description available";
  }
  return text;
}

void Emit(const char* format,
          const std::vector<uint8_t>& data,
          bool concealed) {
  if (!g_sink) {
    return;
  }
  g_sink->Success(EncodableValue(EncodableMap{
      {EncodableValue("format"), EncodableValue(format)},
      {EncodableValue("data"), EncodableValue(data)},
      {EncodableValue("concealed"), EncodableValue(concealed)},
  }));
}

void HandleWrite(const EncodableMap& args,
                 flutter::MethodResult<EncodableValue>* result) {
  const auto format_it = args.find(EncodableValue("format"));
  const std::string* format =
      format_it == args.end() ? nullptr
                             : std::get_if<std::string>(&format_it->second);
  const auto data_it = args.find(EncodableValue("data"));
  const std::vector<uint8_t>* data =
      data_it == args.end()
          ? nullptr
          : std::get_if<std::vector<uint8_t>>(&data_it->second);
  if (format == nullptr || data == nullptr) {
    result->Error("bad_args", "format and data required");
    return;
  }

  // Everything is validated before the clipboard is opened. EmptyClipboard is
  // what makes a write possible and it is also what destroys whatever the user
  // had copied: discovering an unsupported format after emptying would wipe
  // their clipboard to accomplish nothing.
  DWORD error = 0;
  if (*format == "text") {
    std::wstring wide;
    if (!Widen(std::string(data->begin(), data->end()), &wide)) {
      result->Error("bad_payload", "text payload is not valid UTF-8");
      return;
    }
    // CF_UNICODETEXT is null-terminated by contract, so the buffer is one
    // wchar_t longer than the text.
    std::vector<wchar_t> buffer(wide.size() + 1, L'\0');
    std::copy(wide.begin(), wide.end(), buffer.begin());
    if (!SetClipboardBlob(CF_UNICODETEXT, buffer.data(),
                          buffer.size() * sizeof(wchar_t), &error)) {
      result->Error("clipboard",
                    "could not write text to the clipboard: error " +
                        std::to_string(error) + " (" +
                        SystemErrorMessage(error) + ")");
      return;
    }
  } else if (*format == "png") {
    if (data->empty()) {
      result->Error("bad_payload", "png payload is empty");
      return;
    }
    const UINT png = PngFormat();
    if (png == 0) {
      result->Error("clipboard",
                    "RegisterClipboardFormat failed for \"PNG\"");
      return;
    }
    if (!SetClipboardBlob(png, data->data(), data->size(), &error)) {
      result->Error("clipboard",
                    "could not write an image to the clipboard: error " +
                        std::to_string(error) + " (" +
                        SystemErrorMessage(error) + ")");
      return;
    }
  } else {
    // Matches the macOS plugin: an unmapped format is reported, not silently
    // written as if it were text. Handing raw PNG bytes to CF_UNICODETEXT --
    // which is what ignoring `format` here would do -- would paste garbage.
    result->Error("unsupported_format",
                  "no clipboard mapping for '" + *format + "'");
    return;
  }
  result->Success();
}

void HandleStart(flutter::MethodResult<EncodableValue>* result) {
  if (ExcludeFormat() == 0) {
    // Refusing to start is the only safe answer. Without this format we cannot
    // tell a password manager's parked secret from ordinary text, and the
    // failure mode of guessing wrong is broadcasting it.
    result->Error("clipboard_privacy",
                  "RegisterClipboardFormat failed for "
                  "ExcludeClipboardContentFromMonitorProcessing, so content "
                  "excluded from clipboard monitors could not be recognised");
    return;
  }
  if (!g_listening && g_window != nullptr) {
    g_listening = AddClipboardFormatListener(g_window) != 0;
    if (!g_listening) {
      const DWORD error = GetLastError();
      result->Error("clipboard_listener",
                    "AddClipboardFormatListener failed: error " +
                        std::to_string(error) + " (" +
                        SystemErrorMessage(error) + ")");
      return;
    }
  }
  if (!g_listening) {
    result->Error("clipboard_listener", "no window to listen on");
    return;
  }
  g_started = true;
  result->Success();
}

void HandleCall(const flutter::MethodCall<EncodableValue>& call,
                std::unique_ptr<flutter::MethodResult<EncodableValue>> result) {
  if (call.method_name() == "write") {
    // get_if, not get: exceptions are disabled in this build
    // (`_HAS_EXCEPTIONS=0`), so a std::get against the wrong alternative would
    // abort the process rather than throw.
    const auto* args = std::get_if<EncodableMap>(call.arguments());
    if (args == nullptr) {
      result->Error("bad_args", "expected a map of arguments");
      return;
    }
    HandleWrite(*args, result.get());
  } else if (call.method_name() == "start") {
    HandleStart(result.get());
  } else if (call.method_name() == "stop") {
    // The listener stays registered -- re-adding it later is the only way back
    // and Add/Remove churn buys nothing -- but `g_started` gates every read, so
    // after `stop` the clipboard is not touched.
    g_started = false;
    result->Success();
  } else {
    result->NotImplemented();
  }
}

}  // namespace

void OnClipboardUpdate() {
  if (!g_started || !g_sink) {
    return;
  }

  if (g_self_write_valid &&
      GetClipboardSequenceNumber() == g_self_write_sequence) {
    g_self_write_valid = false;
    return;
  }

  if (IsClipboardFormatAvailable(ExcludeFormat())) {
    // Reported, so the skip stays countable, but the bytes are never read.
    // This is a password manager telling us it has parked a secret on the
    // clipboard for a few seconds. ClipboardSync drops concealed content
    // without looking at `data`, so copying that secret across the platform
    // channel into the Dart heap would buy nothing and risk everything.
    Emit("text", {}, true);
    return;
  }

  std::vector<uint8_t> png;
  std::string text;
  bool have_png = false;
  bool have_text = false;
  {
    ClipboardLock lock(g_window);
    if (!lock.held()) {
      return;
    }
    // PNG first: an image on the clipboard usually also carries a text
    // representation (a filename, a source URL), and the image is what was
    // copied.
    have_png = ReadClipboardPng(&png);
    if (!have_png) {
      have_text = ReadClipboardText(&text);
    }
  }
  // Emitted outside the lock: the sink reaches into the engine, and holding
  // the clipboard open across that would lock every other process out of it
  // for the duration.
  if (have_png) {
    Emit("png", png, false);
  } else if (have_text) {
    Emit("text", std::vector<uint8_t>(text.begin(), text.end()), false);
  }
  // Anything else -- a file drop, RTF only, a custom type -- is ignored:
  // `supportedClipboardFormats` is {text, png} and there is nothing useful to
  // send.
}

void RegisterClipboardPlugin(flutter::BinaryMessenger* messenger, HWND window) {
  g_window = window;

  g_methods = std::make_unique<flutter::MethodChannel<EncodableValue>>(
      messenger, "com.omnifi/clipboard",
      &flutter::StandardMethodCodec::GetInstance());
  g_methods->SetMethodCallHandler(HandleCall);

  g_events = std::make_unique<flutter::EventChannel<EncodableValue>>(
      messenger, "com.omnifi/clipboard/changes",
      &flutter::StandardMethodCodec::GetInstance());
  g_events->SetStreamHandler(
      std::make_unique<flutter::StreamHandlerFunctions<EncodableValue>>(
          [](const EncodableValue*,
             std::unique_ptr<flutter::EventSink<EncodableValue>>&& sink)
              -> std::unique_ptr<flutter::StreamHandlerError<EncodableValue>> {
            g_sink = std::move(sink);
            return nullptr;
          },
          [](const EncodableValue*)
              -> std::unique_ptr<flutter::StreamHandlerError<EncodableValue>> {
            g_sink.reset();
            return nullptr;
          }));
}

void UnregisterClipboardPlugin() {
  if (g_listening && g_window != nullptr) {
    RemoveClipboardFormatListener(g_window);
  }
  g_listening = false;
  g_started = false;
  g_window = nullptr;
  // Destroying a channel does not unregister its handler -- the messenger owns
  // that -- so the handlers are cleared explicitly first, while the messenger
  // is still alive.
  if (g_methods) {
    g_methods->SetMethodCallHandler(nullptr);
  }
  if (g_events) {
    g_events->SetStreamHandler(nullptr);
  }
  g_sink.reset();
  g_methods.reset();
  g_events.reset();
}
