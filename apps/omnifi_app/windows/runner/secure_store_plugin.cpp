#include "secure_store_plugin.h"

#include <windows.h>
// wincred.h has no includes of its own and must follow windows.h.
#include <wincred.h>

#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>

#include <climits>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>

namespace {

using flutter::EncodableMap;
using flutter::EncodableValue;

// Credentials live under "OmniFi/<key>" as CRED_TYPE_GENERIC entries. The blob
// is encrypted by the Credential Manager against the logged-on user, so
// another user on the same machine cannot read it.
constexpr char kTargetPrefix[] = "OmniFi/";

// Shown in the Credential Manager UI. CRED_TYPE_GENERIC does not require a
// user name, but an entry without one displays as a blank row, which makes the
// manual "is the credential actually there?" check needlessly hard.
constexpr wchar_t kUserName[] = L"OmniFi";

std::unique_ptr<flutter::MethodChannel<EncodableValue>> g_channel;

// UTF-8 to UTF-16. Returns false if |utf8| is not well-formed UTF-8 --
// MB_ERR_INVALID_CHARS is what makes this a validation and not a silent
// substitution of U+FFFD.
bool Widen(const std::string& utf8, std::wstring* out) {
  out->clear();
  if (utf8.empty()) {
    return true;
  }
  if (utf8.size() > static_cast<size_t>(INT_MAX)) {
    return false;
  }
  const int length = static_cast<int>(utf8.size());
  // An explicit source length (rather than -1) means the returned count
  // excludes the terminator, so there is no off-by-one to get wrong.
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

// Whether |utf8| is well-formed UTF-8, without paying for the conversion.
bool IsValidUtf8(const std::string& utf8) {
  if (utf8.empty()) {
    return true;
  }
  if (utf8.size() > static_cast<size_t>(INT_MAX)) {
    return false;
  }
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                             static_cast<int>(utf8.size()), nullptr, 0) > 0;
}

// UTF-16 to UTF-8, for error text coming back out of Windows.
std::string Narrow(const wchar_t* wide, size_t wide_length) {
  if (wide_length == 0 || wide_length > static_cast<size_t>(INT_MAX)) {
    return {};
  }
  const int length = static_cast<int>(wide_length);
  const int size =
      WideCharToMultiByte(CP_UTF8, 0, wide, length, nullptr, 0, nullptr,
                          nullptr);
  if (size <= 0) {
    return {};
  }
  std::string out;
  out.resize(static_cast<size_t>(size));
  const int written = WideCharToMultiByte(CP_UTF8, 0, wide, length, out.data(),
                                          size, nullptr, nullptr);
  if (written != size) {
    return {};
  }
  return out;
}

// The system's own words for |error|, so the message that reaches Dart says
// what went wrong rather than only which number went wrong. This is the
// Windows equivalent of `SecCopyErrorMessageString` on the macOS side.
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
    // FormatMessage terminates its text with CRLF.
    while (length != 0 &&
           (buffer[length - 1] == L'\n' || buffer[length - 1] == L'\r')) {
      --length;
    }
    text = Narrow(buffer, length);
  }
  if (buffer != nullptr) {
    LocalFree(buffer);
  }
  if (text.empty()) {
    text = "no description available";
  }
  return text;
}

// Mirrors the macOS plugin's three-way outcome. `kAbsent` is a *statement*,
// not a failure: it is the one condition that may reach Dart as null.
enum class CredStatus { kOk, kAbsent, kFailed };

CredStatus ReadCredential(const std::wstring& target,
                          std::string* value,
                          DWORD* error) {
  PCREDENTIALW cred = nullptr;
  if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
    const DWORD last = GetLastError();
    if (last == static_cast<DWORD>(ERROR_NOT_FOUND)) {
      return CredStatus::kAbsent;
    }
    *error = last;
    return CredStatus::kFailed;
  }
  // CredentialBlob is *bytes* with an explicit length. It is not a wide
  // string and it is not null-terminated, so CredentialBlobSize is the only
  // thing that says where the value ends; reading to a NUL would truncate at
  // the first zero byte of anything binary stored here.
  if (cred->CredentialBlobSize != 0 && cred->CredentialBlob != nullptr) {
    value->assign(reinterpret_cast<const char*>(cred->CredentialBlob),
                  cred->CredentialBlobSize);
  } else {
    value->clear();
  }
  CredFree(cred);
  return CredStatus::kOk;
}

bool WriteCredential(const std::wstring& target,
                     const std::string& value,
                     DWORD* error) {
  if (value.size() > static_cast<size_t>(CRED_MAX_CREDENTIAL_BLOB_SIZE)) {
    // CredWriteW would fail this with a bare ERROR_INVALID_PARAMETER, which
    // says nothing about which parameter.
    *error = ERROR_INVALID_PARAMETER;
    return false;
  }
  CREDENTIALW cred = {};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(target.c_str());
  cred.UserName = const_cast<LPWSTR>(kUserName);
  cred.CredentialBlobSize = static_cast<DWORD>(value.size());
  cred.CredentialBlob =
      reinterpret_cast<LPBYTE>(const_cast<char*>(value.data()));
  // LOCAL_MACHINE, deliberately, and not ENTERPRISE. ENTERPRISE roams the
  // credential to every machine the user signs in to, which would clone this
  // device's private key onto other devices -- the opposite of what a
  // per-device identity means. This is the counterpart of
  // `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` on the Apple side.
  // SESSION would be lost at logoff and mint a new identity on next sign-in.
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  if (!CredWriteW(&cred, 0)) {
    *error = GetLastError();
    return false;
  }
  return true;
}

bool DeleteCredential(const std::wstring& target, DWORD* error) {
  if (CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0)) {
    return true;
  }
  const DWORD last = GetLastError();
  // Deleting what is not there is the intended end state, not a failure.
  if (last == ERROR_NOT_FOUND) {
    return true;
  }
  *error = last;
  return false;
}

void Fail(flutter::MethodResult<EncodableValue>* result,
          const std::string& what,
          DWORD error) {
  result->Error("credential_store",
                "credential store failed while " + what + ": error " +
                    std::to_string(error) + " (" + SystemErrorMessage(error) +
                    ")",
                EncodableValue(static_cast<int32_t>(error)));
}

// Every failure is reported and none is swallowed.
//
// `read` returning null is not "something went wrong", it is the specific
// statement "this device has no such entry" -- which `loadOrCreateIdentity`
// reads as "first run, mint a new identity". Mapping a Credential Manager
// fault to null would therefore not degrade gracefully: it would silently
// regenerate this device's ID and keypair and orphan it from every peer it had
// already paired with. So only ERROR_NOT_FOUND becomes null; every other
// Win32 error becomes a PlatformException, and the Dart side lets it throw.
//
// The same reasoning applies to `write`: an unchecked CredWriteW that failed
// would leave the process running on an identity that was never persisted, and
// the next launch would mint another one.
void HandleCall(const flutter::MethodCall<EncodableValue>& call,
                std::unique_ptr<flutter::MethodResult<EncodableValue>> result) {
  const auto* args = std::get_if<EncodableMap>(call.arguments());
  if (args == nullptr) {
    result->Error("bad_args", "expected a map of arguments");
    return;
  }
  const auto key_it = args->find(EncodableValue("key"));
  // get_if, not get: exceptions are disabled in this build
  // (`_HAS_EXCEPTIONS=0` in the top-level CMakeLists), so a std::get against
  // the wrong alternative would abort the process rather than throw.
  const std::string* key = key_it == args->end()
                               ? nullptr
                               : std::get_if<std::string>(&key_it->second);
  if (key == nullptr) {
    result->Error("bad_args", "key required");
    return;
  }

  std::wstring target;
  if (!Widen(kTargetPrefix + *key, &target)) {
    result->Error("bad_args", "key is not valid UTF-8");
    return;
  }

  DWORD error = 0;
  if (call.method_name() == "read") {
    std::string value;
    switch (ReadCredential(target, &value, &error)) {
      case CredStatus::kAbsent:
        result->Success(EncodableValue());
        return;
      case CredStatus::kFailed:
        Fail(result.get(), "reading " + *key, error);
        return;
      case CredStatus::kOk:
        break;
    }
    // Present but undecodable is a fault, not an absence. Returning null here
    // would put us straight back on the regenerate-the-identity path.
    if (!IsValidUtf8(value)) {
      result->Error("credential_store",
                    "credential store entry for " + *key +
                        " is not valid UTF-8");
      return;
    }
    result->Success(EncodableValue(value));
  } else if (call.method_name() == "write") {
    const auto value_it = args->find(EncodableValue("value"));
    const std::string* value = value_it == args->end()
                                   ? nullptr
                                   : std::get_if<std::string>(&value_it->second);
    if (value == nullptr) {
      result->Error("bad_args", "value required");
      return;
    }
    // CredWriteW replaces an existing entry, so there is no delete-then-add
    // window in which the identity exists nowhere.
    if (!WriteCredential(target, *value, &error)) {
      Fail(result.get(), "writing " + *key, error);
      return;
    }
    result->Success();
  } else if (call.method_name() == "delete") {
    if (!DeleteCredential(target, &error)) {
      Fail(result.get(), "deleting " + *key, error);
      return;
    }
    result->Success();
  } else {
    result->NotImplemented();
  }
}

}  // namespace

void RegisterSecureStorePlugin(flutter::BinaryMessenger* messenger) {
  g_channel = std::make_unique<flutter::MethodChannel<EncodableValue>>(
      messenger, "com.omnifi/secure_store",
      &flutter::StandardMethodCodec::GetInstance());
  g_channel->SetMethodCallHandler(HandleCall);
}
