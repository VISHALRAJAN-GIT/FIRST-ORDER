/**
 * QR rendering.
 *
 * The security-relevant work is all done by the time we get here: the string we
 * render is already signed, contains no PII, no pricing and no credentials. This
 * module is only responsible for producing a scannable image, and for keeping the
 * payload small enough that a phone camera at a gate can read it reliably.
 *
 * ## Payload size is a correctness concern, not an optimisation
 *
 * A dense QR code fails in the exact environment that matters: a dim entrance
 * queue, a scratched screen, an old phone, a scanner held at an angle. So the
 * encoder is capped by default at the lowest error-correction level that still
 * tolerates real-world damage, and the security team can raise it for venues
 * with worse conditions.
 *
 * `M` is the deliberate default. `H` costs roughly 30% more modules for
 * redundancy against occlusion, which on a phone screen mostly protects against
 * fingerprints — and pushes the payload past what a camera reads comfortably at
 * a gate. Venues that need `H` can set it.
 */

import QRCode from 'qrcode';
import { SecurityError } from '../core/errors';
import type { TicketEnvelope } from '../tickets/payload';
import { serializeEnvelope } from '../tickets/payload';

export type QRErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';

export interface QrRenderOptions {
  /** Pixel size of the square image. Default 512. */
  readonly size?: number;
  /** Quiet-zone width in modules. Default 4, the spec minimum. */
  readonly margin?: number;
  readonly errorCorrectionLevel?: QRErrorCorrectionLevel;
  /** Render dark modules as near-black for better contrast on cheap scanners. */
  readonly darkColor?: string;
  readonly lightColor?: string;
}

export interface RenderedQr {
  /** PNG as a base64 data URI, suitable for an `<img src>`. */
  readonly dataUri: string;
  /** Raw PNG bytes. */
  readonly buffer: Buffer;
  /** The exact signed string encoded, for audit and for re-derivation. */
  readonly encoded: string;
}

const DEFAULTS = {
  size: 512,
  margin: 4,
  errorCorrectionLevel: 'M' as QRErrorCorrectionLevel,
  darkColor: '#000000',
  lightColor: '#FFFFFF',
};

/** Serialize an envelope to the exact string that will be signed/verified. */
export function encodeEnvelope(envelope: TicketEnvelope): string {
  return serializeEnvelope(envelope);
}

export async function renderQrDataUri(
  envelope: TicketEnvelope,
  options: QrRenderOptions = {},
): Promise<string> {
  const settings = { ...DEFAULTS, ...options };
  const encoded = encodeEnvelope(envelope);

  try {
    return await QRCode.toDataURL(encoded, {
      errorCorrectionLevel: settings.errorCorrectionLevel,
      margin: settings.margin,
      width: settings.size,
      color: { dark: settings.darkColor, light: settings.lightColor },
    });
  } catch (error) {
    throw new SecurityError('INTERNAL_ERROR', 'Failed to render ticket QR code', { cause: error });
  }
}

export async function renderQrBuffer(
  envelope: TicketEnvelope,
  options: QrRenderOptions = {},
): Promise<RenderedQr> {
  const settings = { ...DEFAULTS, ...options };
  const encoded = encodeEnvelope(envelope);

  try {
    const buffer = await QRCode.toBuffer(encoded, {
      errorCorrectionLevel: settings.errorCorrectionLevel,
      margin: settings.margin,
      width: settings.size,
      color: { dark: settings.darkColor, light: settings.lightColor },
      type: 'png',
    });
    const dataUri = await QRCode.toDataURL(encoded, {
      errorCorrectionLevel: settings.errorCorrectionLevel,
      margin: settings.margin,
      width: settings.size,
      color: { dark: settings.darkColor, light: settings.lightColor },
    });
    return { dataUri, buffer, encoded };
  } catch (error) {
    throw new SecurityError('INTERNAL_ERROR', 'Failed to render ticket QR code', { cause: error });
  }
}

export async function renderQrSvg(
  envelope: TicketEnvelope,
  options: QrRenderOptions = {},
): Promise<string> {
  const settings = { ...DEFAULTS, ...options };
  const encoded = encodeEnvelope(envelope);

  try {
    return await QRCode.toString(encoded, {
      errorCorrectionLevel: settings.errorCorrectionLevel,
      margin: settings.margin,
      width: settings.size,
      color: { dark: settings.darkColor, light: settings.lightColor },
      type: 'svg',
    });
  } catch (error) {
    throw new SecurityError('INTERNAL_ERROR', 'Failed to render ticket QR code', { cause: error });
  }
}
