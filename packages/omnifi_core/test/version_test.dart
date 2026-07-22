import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('protocol version is 1', () {
    expect(omnifiProtocolVersion, 1);
  });
}
