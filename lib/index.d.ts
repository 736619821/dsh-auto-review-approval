import z from "@deepseek-ai/schemastery";
import { z as z$1 } from "zod";
import { Context } from "@deepseek-ai/cordis";
import "@deepseek-ai/dsh-session";
/** User-selectable automatic review modes. */
type ReviewMode = 'manual' | 'smart' | 'unattended';
/** Browser projection carrying the current independent review mode. */
interface ReviewModeProjection {
  mode: ReviewMode;
}
/** Internal projection state for pairing built-in command lifecycle events. */
interface ReviewModeProjectionState extends ReviewModeProjection {
  readonly fallback: ReviewMode;
  readonly origin: 'default' | 'legacy' | 'independent';
  readonly pending?: Readonly<Record<string, ReviewMode>> | undefined;
}
declare module '@deepseek-ai/dsh-session-projection/types' {
  interface SessionProjectionMap {
    /** Automatic approval review mode for the session. */
    approvalReview: ReviewModeProjection;
  }
  interface SessionProjectionStateMap {
    /** Host fold state for the automatic approval review mode. */
    approvalReview: ReviewModeProjectionState;
  }
}
declare module '@deepseek-ai/dsh-session/types' {
  interface SessionEventMap {
    /** Legacy pre-rc.4 review mode event, retained only for one-way migration. */
    'smart-approval/mode': {
      mode: ReviewMode;
    };
  }
}
/** Cordis plugin name used in diagnostics. */
declare const name = "dsh-smart-approval";
/** Services that must exist before the answerer registers. */
declare const inject: string[];
/** Runtime configuration for smart approval. */
interface Config {
  /** Review mode used by sessions without an explicit selection. */
  readonly defaultMode?: ReviewMode;
  /** Optional dedicated reviewer provider; configure together with reviewerModel. */
  readonly reviewerProvider?: string;
  /** Optional dedicated reviewer model; configure together with reviewerProvider. */
  readonly reviewerModel?: string;
  /** Whole reviewer-call deadline in milliseconds. */
  readonly timeoutMs?: number;
  /** Maximum reviewer output tokens. */
  readonly maxTokens?: number;
  /** Maximum raw character count of one tool argument object. */
  readonly maxToolArgumentChars?: number;
  /** Number of current and recent direct-user messages included as authorization context. */
  readonly maxUserMessages?: number;
  /** Maximum combined character count of included direct-user messages. */
  readonly maxUserContextChars?: number;
  /** Maximum persisted decision-audit entries per Session lifecycle; 0 disables the audit. */
  readonly decisionLogSize?: number;
}
/** Cordis configuration schema with conservative bounded defaults. */
declare const Config: z<Config>;
/**
 * Register a prepended approval answerer. Mode is resolved from the durable
 * sidecar for every request, so /approval-mode changes take effect without
 * plugin reload or extension events in the Session log.
 * @param ctx - Cordis context with DSH approval, session, storage, and LLM services.
 * @param config - optional reviewer route and bounded context limits.
 */
declare function apply(ctx: Context, config?: Config): Promise<void>;
export { Config, apply, inject, name };
//# sourceMappingURL=index.d.ts.map