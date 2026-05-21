namespace ASCF;

/// <summary> transforms encoded bytes at a stream boundary </summary>
public delegate void AscfBufferTransform(Span<byte> buffer);
