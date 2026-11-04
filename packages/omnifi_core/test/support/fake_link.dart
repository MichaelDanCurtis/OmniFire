// The fake link now lives in the library (`lib/src/transport/
// fake_link_factory.dart`) so that the Flutter app's own tests can use it
// too. This file is a thin compatibility shim for the suites written
// against the old location.
//
// The import is not redundant with the export: the export re-publishes the
// names to importers, while the typedef below needs `FakeLinkFactory` in
// *this* file's own scope.
import 'package:omnifi_core/omnifi_core.dart';

export 'package:omnifi_core/omnifi_core.dart'
    show FakeLinkFactory, ThrowingCloseLink;

// Existing tests refer to `FakeLink`; keep that name working.
typedef FakeLink = FakeLinkFactory;
