import 'dart:typed_data';

/// Hard ceiling on a single frame's payload, in bytes.
const int maxFrameBytes = 1048576;

const int _prefixBytes = 4;

class FrameTooLargeError implements Exception {
  const FrameTooLargeError(this.declared);
  final int declared;
  @override
  String toString() =>
      'FrameTooLargeError: $declared bytes exceeds cap of $maxFrameBytes';
}

Uint8List encodeFrame(List<int> payload) {
  if (payload.length > maxFrameBytes) {
    throw FrameTooLargeError(payload.length);
  }
  final out = Uint8List(_prefixBytes + payload.length);
  ByteData.view(out.buffer).setUint32(0, payload.length);
  out.setRange(_prefixBytes, out.length, payload);
  return out;
}

/// Accumulates socket reads and emits complete frames.
///
/// A single chunk may contain zero, one, or many frames, and a frame may
/// straddle any number of chunks — including a split inside the length
/// prefix itself.
class FrameDecoder {
  final BytesBuilder _buffer = BytesBuilder(copy: true);

  void reset() => _buffer.clear();

  Iterable<Uint8List> addChunk(List<int> chunk) sync* {
    _buffer.add(chunk);
    final bytes = _buffer.toBytes();
    var offset = 0;

    while (bytes.length - offset >= _prefixBytes) {
      final length = ByteData.view(bytes.buffer, bytes.offsetInBytes + offset)
          .getUint32(0);
      if (length > maxFrameBytes) {
        throw FrameTooLargeError(length);
      }
      if (bytes.length - offset - _prefixBytes < length) {
        break;
      }
      final start = offset + _prefixBytes;
      yield Uint8List.sublistView(bytes, start, start + length);
      offset = start + length;
    }

    _buffer.clear();
    if (offset < bytes.length) {
      _buffer.add(Uint8List.sublistView(bytes, offset));
    }
  }
}
