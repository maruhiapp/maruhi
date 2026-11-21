import { Layer } from "effect";
import { Digest, SecureRandom, Signature } from "effect/crypto";

export const cryptoServicesLayer: Layer.Layer<
  SecureRandom.SecureRandom | Digest.Digest | Signature.Signature
> = Layer.mergeAll(
  SecureRandom.layerWebCrypto,
  Digest.layerWebCrypto,
  Signature.layerWebCrypto.pipe(Layer.provide(SecureRandom.layerWebCrypto)),
);
