<?php

namespace JayAnta\ThreatDetection\Integration;

/**
 * The one place in this package that knows ai-guard exists.
 *
 * `jayanta/laravel-ai-guard` publishes a convention it calls
 * `ai-guard.verdict/1`: three named events and a request attribute that report
 * *who a client is* — a known bot category, a verified agent, a crawler caught
 * impersonating one. It is a convention rather than an API, which is the whole
 * reason this package can read it.
 *
 * Every name below is a **string**. Nothing here is imported, autoloaded,
 * instantiated or class_exists()'d, and there is no Composer dependency in
 * either direction. Laravel accepts a class-name string as an event name
 * whether or not the class exists, so a listener registered against one of
 * these is simply never called when ai-guard is absent — which is the normal
 * case, and costs nothing.
 *
 * If ai-guard ever breaks its contract it becomes `ai-guard.verdict/2`, and
 * every payload is checked against SCHEMA before it is read. An unrecognised
 * schema is ignored rather than guessed at.
 *
 * @see https://github.com/jay123anta/laravel-ai-guard — "Interop Contract"
 */
final class AiGuardContract
{
    /** Payloads that do not carry exactly this are ignored. */
    public const SCHEMA = 'ai-guard.verdict/1';

    public const EVENT_BOT_CLASSIFIED = 'JayAnta\\AiGuard\\Events\\BotClassified';

    public const EVENT_AGENT_VERIFIED = 'JayAnta\\AiGuard\\Events\\AgentVerified';

    public const EVENT_SPOOFED_BOT = 'JayAnta\\AiGuard\\Events\\SpoofedBotDetected';

    /**
     * Set on the request once ai-guard's middleware has evaluated it. Present
     * even when ai-guard's own interop events are switched off, so it is the
     * more reliable of the two channels — when their middleware runs first.
     */
    public const REQUEST_ATTRIBUTE = 'ai_guard.verdict';

    public const STATUS_VERIFIED = 'verified';

    public const STATUS_SPOOFED = 'spoofed';

    /** @return array<int, string> The event names worth listening for. */
    public static function events(): array
    {
        return [
            self::EVENT_BOT_CLASSIFIED,
            self::EVENT_AGENT_VERIFIED,
            self::EVENT_SPOOFED_BOT,
        ];
    }
}
