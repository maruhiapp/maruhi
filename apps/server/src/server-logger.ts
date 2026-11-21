import { Layer, Logger } from "effect";

export const CAUSE_ONLY_LINE = "a log call carried no message (Cause-only); add a static message";

const serverLogger = Logger.make<unknown, void>(({ logLevel, message }) => {
  const given: readonly unknown[] = Array.isArray(message) ? message : [message];
  const parts: readonly unknown[] = given.length === 0 ? [CAUSE_ONLY_LINE] : given;
  switch (logLevel) {
    case "Warn":
      console.warn(...parts);
      return;
    case "Error":
    case "Fatal":
      console.error(...parts);
      return;
    default:
      return;
  }
});

export const ServerLoggerLive: Layer.Layer<never> = Logger.layer([serverLogger]);
