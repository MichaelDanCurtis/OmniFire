import 'dart:typed_data';

/// Hard ceiling on a single frame's payload, in bytes.
const int maxFrameBytes = 1048576;

const int _prefixBytes = 4;

/// Thrown when a decoded length prefix declares a payload larger than
/// [maxFrameBytes].
///
/// Once this is thrown, the [FrameDecoder] that threw it has discarded its
/// internal buffer and is desynchronised from the byte stream: the length
/// prefix that would tell us where the next frame begins is the thing that
/// was just rejected, so there is no safe point to resume decoding from.
/// The connection this decoder was reading must be closed — do not keep
/// feeding bytes to the same decoder instance.
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

  /// Appends [chunk] to the internal buffer and returns every complete
  /// frame that can now be decoded.
  ///
  /// The buffering happens as soon as this method is called, regardless of
  /// whether the returned [Iterable] is ever iterated — so `addChunk(data)`
  /// used as a bare statement (e.g. `socket.listen(decoder.addChunk)`) does
  /// not silently drop bytes.
  ///
  /// Throws [FrameTooLargeError] if a decoded length prefix declares a
  /// payload larger than [maxFrameBytes]. When that happens the internal
  /// buffer is cleared before the error is thrown: the decoder has lost
  /// synchronisation with the stream and must not be reused — close the
  /// connection instead.
  List<Uint8List> addChunk(List<int> chunk) {
    _buffer.add(chunk);
    return _decode().toList();
  }

  Iterable<Uint8List> _decode() sync* {
    final bytes = _buffer.toBytes();
    var offset = 0;

    while (bytes.length - offset >= _prefixBytes) {
      final length = ByteData.view(bytes.buffer, bytes.offsetInBytes + offset)
          .getUint32(0);
      if (length > maxFrameBytes) {
        // The rejected length prefix is the only thing that would tell us
        // where the next frame starts, so there is no safe resume point.
        // Drop everything so a caller that (incorrectly) keeps feeding this
        // decoder cannot have stale bytes — including already-yielded
        // frames — re-parsed and re-emitted.
        _buffer.clear();
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
