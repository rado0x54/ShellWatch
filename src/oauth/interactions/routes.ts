import type { FastifyInstance } from "fastify";
import type Provider from "oidc-provider";
import type { ShellWatchDB } from "../../db/connection.js";
import type { AccountRepository } from "../../db/repositories/account-repo.js";
import {
  type AuthenticationResponseLike,
  verifyPasskeyAssertion,
} from "../../webauthn/passkey-verify.js";
import { renderConsentPage, renderLoginPage } from "./render.js";

export interface RegisterInteractionRoutesParams {
  app: FastifyInstance;
  provider: Provider;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];
}

/**
 * Fastify routes that back panva's redirect-based interaction flow.
 *
 * When an MCP client hits `/oidc/auth` and no user is signed in, panva
 * redirects the browser to `/oidc/interaction/:uid`. We own that URL
 * and the `/login`, `/confirm`, and `/abort` sub-routes underneath it.
 * Each handler inspects the interaction via
 * `provider.interactionDetails` and — once the appropriate step is
 * complete — calls `provider.interactionFinished` to hand control back
 * to panva, which resumes the original authorization request.
 *
 * The passkey ceremony itself is shared with the Web UI's
 * `/api/webauthn/login/verify` — both call
 * {@link verifyPasskeyAssertion}. After a successful verify the OAuth
 * path never sets a `sw_session` cookie (the interaction is scoped to
 * this single OAuth flow) — it just tells panva who authenticated.
 */
export function registerInteractionRoutes(params: RegisterInteractionRoutesParams): void {
  const { app, provider } = params;

  // GET /oidc/interaction/:uid — renders login or consent HTML
  app.get<{ Params: { uid: string } }>("/oidc/interaction/:uid", async (request, reply) => {
    let details;
    try {
      details = await provider.interactionDetails(request.raw, reply.raw);
    } catch {
      reply.status(404).send({ error: "Interaction not found or expired" });
      return;
    }

    // Resolve the client name for display. Anonymous DCR means the
    // `client_name` is attacker-supplied; we show it exactly as stored
    // but the consent page labels it as client-reported.
    const client = await provider.Client.find(details.params.client_id as string);
    const clientName =
      (client?.clientName as string | undefined) ?? details.params.client_id ?? "unknown client";

    if (details.prompt.name === "login") {
      reply.type("text/html; charset=utf-8");
      return renderLoginPage({
        uid: details.uid,
        clientName: String(clientName),
        rpId: params.rpId,
      });
    }

    if (details.prompt.name === "consent") {
      const accountId = details.session?.accountId;
      if (!accountId) {
        // Panva asked for consent but session has no account — unusual.
        reply.status(400).send({ error: "No authenticated account in interaction session" });
        return;
      }
      const account = await params.accountRepo.findById(accountId);
      const scope = (details.params.scope as string | undefined) ?? "";
      const resource = (details.params.resource as string | undefined) ?? "";
      reply.type("text/html; charset=utf-8");
      return renderConsentPage({
        uid: details.uid,
        clientName: String(clientName),
        accountName: account?.name ?? accountId,
        scopes: scope.split(/\s+/).filter(Boolean),
        redirectUri: String(details.params.redirect_uri ?? ""),
        resource,
      });
    }

    reply.status(400).send({
      error: `Unsupported interaction prompt: ${details.prompt.name}`,
    });
    return;
  });

  // POST /oidc/interaction/:uid/login — passkey verify + interactionFinished
  app.post<{
    Params: { uid: string };
    Body: { challengeId: string; credential: AuthenticationResponseLike };
  }>("/oidc/interaction/:uid/login", async (request, reply) => {
    let details;
    try {
      details = await provider.interactionDetails(request.raw, reply.raw);
    } catch {
      reply.status(404);
      return { error: "Interaction not found or expired" };
    }
    if (details.prompt.name !== "login") {
      reply.status(400);
      return { error: `Cannot submit login for ${details.prompt.name} prompt` };
    }

    const verifyResult = await verifyPasskeyAssertion({
      db: params.db,
      accountRepo: params.accountRepo,
      rpId: params.rpId,
      trustedOrigins: params.trustedOrigins,
      challengeId: request.body.challengeId,
      credential: request.body.credential,
    });
    if (!verifyResult.ok) {
      reply.status(verifyResult.status);
      return { error: verifyResult.error };
    }

    const redirect = await provider.interactionResult(
      request.raw,
      reply.raw,
      { login: { accountId: verifyResult.accountId } },
      { mergeWithLastSubmission: false },
    );
    return { redirect };
  });

  // POST /oidc/interaction/:uid/confirm — consent given
  app.post<{ Params: { uid: string } }>(
    "/oidc/interaction/:uid/confirm",
    async (request, reply) => {
      let details;
      try {
        details = await provider.interactionDetails(request.raw, reply.raw);
      } catch {
        reply.status(404).send({ error: "Interaction not found or expired" });
        return;
      }
      if (details.prompt.name !== "consent") {
        reply.status(400).send({ error: `Cannot confirm ${details.prompt.name} prompt` });
        return;
      }

      const accountId = details.session?.accountId;
      if (!accountId) {
        reply.status(400).send({ error: "No authenticated account in interaction session" });
        return;
      }

      // Locate / create the Grant, add the requested scopes + resources,
      // persist, and tell panva which grantId to issue the code against.
      const clientId = String(details.params.client_id);
      const scope = String(details.params.scope ?? "");
      const resource = String(details.params.resource ?? "");

      const grantId = details.grantId
        ? details.grantId
        : await (async () => {
            const grant = new provider.Grant({ accountId, clientId });
            if (scope) grant.addOIDCScope(scope);
            if (resource && scope) grant.addResourceScope(resource, scope);
            return grant.save();
          })();

      // If a grantId already existed, ensure it has the scopes the
      // client is currently asking for (a second call from the same
      // client might request more).
      if (details.grantId) {
        const grant = await provider.Grant.find(details.grantId);
        if (grant) {
          if (scope) grant.addOIDCScope(scope);
          if (resource && scope) grant.addResourceScope(resource, scope);
          await grant.save();
        }
      }

      const redirect = await provider.interactionResult(
        request.raw,
        reply.raw,
        { consent: { grantId } },
        { mergeWithLastSubmission: true },
      );
      return { redirect };
    },
  );

  // POST /oidc/interaction/:uid/abort — user denied or cancelled
  app.post<{ Params: { uid: string } }>("/oidc/interaction/:uid/abort", async (request, reply) => {
    let details;
    try {
      details = await provider.interactionDetails(request.raw, reply.raw);
    } catch {
      reply.status(404);
      return { error: "Interaction not found or expired" };
    }
    void details;
    const redirect = await provider.interactionResult(
      request.raw,
      reply.raw,
      {
        error: "access_denied",
        error_description: "User denied the authorization request",
      },
      { mergeWithLastSubmission: false },
    );
    return { redirect };
  });
}
