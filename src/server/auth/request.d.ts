import "fastify";

declare module "fastify" {
  interface FastifyRequest {
    accountId: string | null;
  }
}
